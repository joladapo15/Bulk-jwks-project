package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

// =============================================================================
// GLOBALS
// =============================================================================

var db *sql.DB

// limiter caps POST /auth at 10 requests per second using a fixed window counter.
var limiter = newFixedWindowLimiter(10)

// =============================================================================
// TYPES
// =============================================================================

// JWK represents a single JSON Web Key.
// Kid MUST be a string so the gradebot can unmarshal it correctly.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the JSON Web Key Set returned by /.well-known/jwks.json
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// =============================================================================
// RATE LIMITER (fixed window counter)
// =============================================================================

// rateLimiter counts requests within a fixed 1-second window.
// Once the count reaches maxPerSecond, all further requests in that window
// are rejected with 429. The window resets automatically each second.
type rateLimiter struct {
	mu           sync.Mutex
	count        int
	maxPerSecond int
	windowStart  time.Time
}

func newFixedWindowLimiter(max int) *rateLimiter {
	return &rateLimiter{
		maxPerSecond: max,
		windowStart:  time.Now(),
	}
}

// allow returns true if the request is within the current window's limit.
func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.windowStart) >= time.Second {
		rl.count = 0
		rl.windowStart = now
	}

	if rl.count >= rl.maxPerSecond {
		return false
	}
	rl.count++
	return true
}

// =============================================================================
// AES-256-GCM ENCRYPTION HELPERS
// =============================================================================

// getAESKey reads NOT_MY_KEY from the environment and decodes it.
// Returns the key bytes and an error rather than calling log.Fatal,
// so that callers (and tests) can handle the failure gracefully.
func getAESKey() ([]byte, error) {
	raw := os.Getenv("NOT_MY_KEY")
	if raw == "" {
		return nil, fmt.Errorf("NOT_MY_KEY environment variable is not set")
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("NOT_MY_KEY must be a 64-character hex string (32 bytes for AES-256)")
	}
	return key, nil
}

// encryptKey encrypts plaintext using AES-256-GCM.
// A random nonce is prepended to the ciphertext so each call produces a unique blob.
func encryptKey(plaintext []byte) ([]byte, error) {
	aesKey, err := getAESKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptKey decrypts a blob produced by encryptKey.
func decryptKey(ciphertext []byte) ([]byte, error) {
	aesKey, err := getAESKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// =============================================================================
// DATABASE / REPOSITORY LAYER
// =============================================================================

// openDatabase opens the SQLite file at the given path.
// Separated from table creation so tests can inject an in-memory database.
func openDatabase(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	return err
}

// createTables creates all three tables if they do not already exist.
// Called by initDB and directly by tests using an in-memory database.
func createTables() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS auth_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_ip TEXT NOT NULL,
			request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)`)
	return err
}

// initDB opens the production SQLite file and creates all tables.
func initDB() {
	if err := openDatabase("totally_not_my_privateKeys.db"); err != nil {
		log.Fatal(err)
	}
	if err := createTables(); err != nil {
		log.Fatal(err)
	}
}

// =============================================================================
// KEY HELPERS
// =============================================================================

// x509Marshal serialises an RSA private key to PKCS#1 DER bytes.
func x509Marshal(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// base64url encodes a big.Int as a Base64url string with no padding.
func base64url(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// generateKey creates a 2048-bit RSA key, encrypts it, and stores it in the DB.
// Pass expired=true to store a key whose expiry is one hour in the past.
func generateKey(expired bool) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("generateKey: rsa.GenerateKey: %v", err)
		return
	}

	exp := time.Now().Add(time.Hour).Unix()
	if expired {
		exp = time.Now().Add(-time.Hour).Unix()
	}

	encrypted, err := encryptKey(x509Marshal(key))
	if err != nil {
		log.Printf("generateKey: encryptKey: %v", err)
		return
	}

	if _, err := db.Exec("INSERT INTO keys(key, exp) VALUES(?, ?)", encrypted, exp); err != nil {
		log.Printf("generateKey: db insert: %v", err)
	}
}

// seedKeys guarantees at least one valid and one expired key exist on startup.
func seedKeys() {
	now := time.Now().Unix()

	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", now).Scan(&count)
	if count == 0 {
		generateKey(false)
	}

	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now).Scan(&count)
	if count == 0 {
		generateKey(true)
	}
}

// getKey fetches one key from the DB, decrypts it, and returns the parsed key.
func getKey(expired bool) (int, *rsa.PrivateKey, error) {
	now := time.Now().Unix()

	var row *sql.Row
	if expired {
		row = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", now)
	} else {
		row = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", now)
	}

	var kid int
	var keyBytes []byte
	if err := row.Scan(&kid, &keyBytes); err != nil {
		return 0, nil, fmt.Errorf("getKey scan: %w", err)
	}

	decrypted, err := decryptKey(keyBytes)
	if err != nil {
		return 0, nil, fmt.Errorf("getKey decrypt: %w", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		return 0, nil, fmt.Errorf("getKey parse: %w", err)
	}
	return kid, key, nil
}

// =============================================================================
// AUTH LOGGING HELPERS
// =============================================================================

// logAuthRequest writes a row to auth_logs after a successful /auth request.
func logAuthRequest(ip string, userID *int) {
	if _, err := db.Exec(
		"INSERT INTO auth_logs(request_ip, user_id) VALUES(?, ?)",
		ip, userID,
	); err != nil {
		log.Printf("logAuthRequest: %v", err)
	}
}

// clientIP returns the most accurate client IP available.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// =============================================================================
// HTTP HANDLERS
// =============================================================================

// registerHandler handles POST /register.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		http.Error(w, "invalid request body: username is required", http.StatusBadRequest)
		return
	}

	password := uuid.NewString()

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		http.Error(w, "internal error generating salt", http.StatusInternalServerError)
		return
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	encoded := base64.RawURLEncoding.EncodeToString(salt) +
		"$" +
		base64.RawURLEncoding.EncodeToString(hash)

	if _, err := db.Exec(
		"INSERT INTO users(username, password_hash, email) VALUES(?, ?, ?)",
		req.Username, encoded, req.Email,
	); err != nil {
		http.Error(w, "username or email already exists", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"password": password})
}

// authHandler issues a signed JWT with rate limiting and audit logging.
func authHandler(w http.ResponseWriter, r *http.Request) {
	if !limiter.allow() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Printf("authHandler: JSON decode: %v", err)
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}

	var userID *int
	if body.Username != "" {
		var id int
		if err := db.QueryRow(
			"SELECT id FROM users WHERE username = ?", body.Username,
		).Scan(&id); err == nil {
			userID = &id
		}
	}

	expired := r.URL.Query().Has("expired")
	kid, key, err := getKey(expired)
	if err != nil {
		log.Printf("authHandler: getKey: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var claims jwt.MapClaims
	if expired {
		claims = jwt.MapClaims{
			"sub": "userABC",
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-1 * time.Hour).Unix(),
		}
	} else {
		claims = jwt.MapClaims{
			"sub": "userABC",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	signed, err := token.SignedString(key)
	if err != nil {
		log.Printf("authHandler: SignedString: %v", err)
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	logAuthRequest(clientIP(r), userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

// jwksHandler returns all currently-valid public keys as a JWKS document.
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()

	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", now)
	if err != nil {
		log.Printf("jwksHandler: db query: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []JWK

	for rows.Next() {
		var kid int
		var keyBytes []byte
		if err := rows.Scan(&kid, &keyBytes); err != nil {
			log.Printf("jwksHandler: scan kid %d: %v", kid, err)
			continue
		}

		decrypted, err := decryptKey(keyBytes)
		if err != nil {
			log.Printf("jwksHandler: decrypt kid %d: %v", kid, err)
			continue
		}

		key, err := x509.ParsePKCS1PrivateKey(decrypted)
		if err != nil {
			log.Printf("jwksHandler: parse kid %d: %v", kid, err)
			continue
		}

		pub := key.PublicKey
		keys = append(keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: fmt.Sprintf("%d", kid),
			Alg: "RS256",
			N:   base64url(pub.N),
			E:   base64url(big.NewInt(int64(pub.E))),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWKS{Keys: keys})
}

// =============================================================================
// ENTRY POINT
// =============================================================================

// setupRoutes maps URL paths to their handlers.
func setupRoutes() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
}

func main() {
	// Validate the encryption key before doing anything else.
	if _, err := getAESKey(); err != nil {
		log.Fatal(err)
	}

	initDB()
	seedKeys()
	setupRoutes()

	log.Println("Server running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
