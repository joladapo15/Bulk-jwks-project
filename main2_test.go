package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"math/big"

	_ "modernc.org/sqlite"
)

const testKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func setupTestDB(t *testing.T) {
	t.Helper()
	os.Setenv("NOT_MY_KEY", testKey)
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("setupTestDB: %v", err)
	}
	if err := createTables(); err != nil {
		t.Fatalf("createTables: %v", err)
	}
	seedKeys()
}

// ---------------------------------------------------------------------------
// getAESKey
// ---------------------------------------------------------------------------

func TestGetAESKeySuccess(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	key, err := getAESKey()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
}

func TestGetAESKeyMissing(t *testing.T) {
	os.Unsetenv("NOT_MY_KEY")
	_, err := getAESKey()
	if err == nil {
		t.Error("expected error when NOT_MY_KEY is unset")
	}
	os.Setenv("NOT_MY_KEY", testKey) // restore
}

func TestGetAESKeyInvalid(t *testing.T) {
	os.Setenv("NOT_MY_KEY", "notvalidhex!!")
	_, err := getAESKey()
	if err == nil {
		t.Error("expected error for invalid hex key")
	}
	os.Setenv("NOT_MY_KEY", testKey) // restore
}

func TestGetAESKeyWrongLength(t *testing.T) {
	os.Setenv("NOT_MY_KEY", "deadbeef") // valid hex but only 4 bytes
	_, err := getAESKey()
	if err == nil {
		t.Error("expected error for wrong-length key")
	}
	os.Setenv("NOT_MY_KEY", testKey) // restore
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	plaintext := []byte("hello world this is a test key blob")
	ciphertext, err := encryptKey(plaintext)
	if err != nil {
		t.Fatalf("encryptKey: %v", err)
	}
	got, err := decryptKey(ciphertext)
	if err != nil {
		t.Fatalf("decryptKey: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptProducesDifferentOutputEachTime(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	plaintext := []byte("same input every time")
	a, _ := encryptKey(plaintext)
	b, _ := encryptKey(plaintext)
	if bytes.Equal(a, b) {
		t.Error("expected different ciphertexts due to random nonce")
	}
}

func TestDecryptShortCiphertextReturnsError(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	_, err := decryptKey([]byte("short"))
	if err == nil {
		t.Error("expected error for short ciphertext, got nil")
	}
}

func TestEncryptFailsWithNoKey(t *testing.T) {
	os.Unsetenv("NOT_MY_KEY")
	_, err := encryptKey([]byte("test"))
	if err == nil {
		t.Error("expected error when NOT_MY_KEY is unset")
	}
	os.Setenv("NOT_MY_KEY", testKey)
}

func TestDecryptFailsWithNoKey(t *testing.T) {
	os.Unsetenv("NOT_MY_KEY")
	_, err := decryptKey([]byte("anydatahere"))
	if err == nil {
		t.Error("expected error when NOT_MY_KEY is unset")
	}
	os.Setenv("NOT_MY_KEY", testKey)
}

// ---------------------------------------------------------------------------
// createTables / openDatabase
// ---------------------------------------------------------------------------

func TestCreateTablesOnFreshDB(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := createTables(); err != nil {
		t.Fatalf("createTables: %v", err)
	}
	// Verify all tables exist
	for _, tbl := range []string{"keys", "users", "auth_logs"} {
		if _, err := db.Exec("SELECT 1 FROM " + tbl + " LIMIT 1"); err != nil {
			t.Errorf("table %s missing after createTables: %v", tbl, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

func TestX509MarshalAndBase64url(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509Marshal(key)
	if len(der) == 0 {
		t.Error("x509Marshal returned empty slice")
	}
	encoded := base64url(big.NewInt(65537))
	if encoded == "" {
		t.Error("base64url returned empty string")
	}
}

func TestGenerateKeyValidPath(t *testing.T) {
	setupTestDB(t)
	before := 0
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&before)
	generateKey(false)
	after := 0
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&after)
	if after <= before {
		t.Error("expected one more valid key after generateKey(false)")
	}
}

func TestGenerateKeyExpiredPath(t *testing.T) {
	setupTestDB(t)
	generateKey(true)
	now := time.Now().Unix()
	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now).Scan(&count)
	if count == 0 {
		t.Error("expected at least one expired key after generateKey(true)")
	}
}

func TestSeedKeysIdempotent(t *testing.T) {
	setupTestDB(t)
	before := 0
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&before)
	seedKeys()
	after := 0
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&after)
	if after != before {
		t.Errorf("seedKeys added keys when it shouldn't: before=%d after=%d", before, after)
	}
}

func TestGetKeyValidAndExpired(t *testing.T) {
	setupTestDB(t)
	_, key, err := getKey(false)
	if err != nil || key == nil {
		t.Errorf("getKey(false) failed: %v", err)
	}
	_, expKey, err := getKey(true)
	if err != nil || expKey == nil {
		t.Errorf("getKey(true) failed: %v", err)
	}
}

func TestGetKeyNoKeysReturnsError(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM keys")
	_, _, err := getKey(false)
	if err == nil {
		t.Error("expected error when no valid keys exist")
	}
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

func TestRateLimiterAllowsUpToLimit(t *testing.T) {
	rl := newFixedWindowLimiter(5)
	for i := 0; i < 5; i++ {
		if !rl.allow() {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterBlocksOverLimit(t *testing.T) {
	rl := newFixedWindowLimiter(5)
	for i := 0; i < 5; i++ {
		rl.allow()
	}
	if rl.allow() {
		t.Error("6th request should be blocked but was allowed")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl := newFixedWindowLimiter(2)
	rl.allow()
	rl.allow()
	if rl.allow() {
		t.Error("3rd request in window should be blocked")
	}
	rl.mu.Lock()
	rl.windowStart = time.Now().Add(-2 * time.Second)
	rl.mu.Unlock()
	if !rl.allow() {
		t.Error("first request in new window should be allowed")
	}
}

// ---------------------------------------------------------------------------
// /register
// ---------------------------------------------------------------------------

func TestRegisterSuccess(t *testing.T) {
	setupTestDB(t)
	body := `{"username":"testuser","email":"test@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	registerHandler(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["password"] == "" {
		t.Error("expected a password in the response")
	}
}

func TestRegisterMissingUsername(t *testing.T) {
	setupTestDB(t)
	body := `{"email":"nouser@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	registerHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRegisterInvalidJSON(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{invalid!"))
	w := httptest.NewRecorder()
	registerHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestRegisterDuplicateUsername(t *testing.T) {
	setupTestDB(t)
	body := `{"username":"dupeuser","email":"dupe@example.com"}`
	req1 := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req1.Header.Set("Content-Type", "application/json")
	registerHandler(httptest.NewRecorder(), req1)
	req2 := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	registerHandler(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 on duplicate, got %d", w2.Code)
	}
}

func TestRegisterWrongMethod(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()
	registerHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// /auth
// ---------------------------------------------------------------------------

func TestAuthReturnsToken(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("expected a token in the response")
	}
}

func TestAuthExpiredToken(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthRateLimited(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(1)
	req1 := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w1 := httptest.NewRecorder()
	authHandler(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w1.Code)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w2 := httptest.NewRecorder()
	authHandler(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
}

func TestAuthWithKnownUsername(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	regBody := `{"username":"authuser","email":"authuser@example.com"}`
	regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	registerHandler(httptest.NewRecorder(), regReq)
	authBody := `{"username":"authuser"}`
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(authBody))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(authBody))
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthWithUnknownUsername(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	authBody := `{"username":"ghost"}`
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(authBody))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(authBody))
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even for unknown user, got %d", w.Code)
	}
}

func TestAuthInvalidJSON(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	badBody := `{invalid json}`
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(badBody))
	req.ContentLength = int64(len(badBody))
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthNoKeysReturns500(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	db.Exec("DELETE FROM keys")
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when no keys exist, got %d", w.Code)
	}
}

func TestAuthXForwardedFor(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// /.well-known/jwks.json
// ---------------------------------------------------------------------------

func TestJWKSReturnsKeys(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp JWKS
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Keys) == 0 {
		t.Error("expected at least one key in JWKS response")
	}
}

func TestJWKSKeyFields(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	var resp JWKS
	json.NewDecoder(w.Body).Decode(&resp)
	for _, k := range resp.Keys {
		if k.Kty != "RSA" {
			t.Errorf("expected kty=RSA, got %s", k.Kty)
		}
		if k.Alg != "RS256" {
			t.Errorf("expected alg=RS256, got %s", k.Alg)
		}
		if k.N == "" || k.E == "" {
			t.Error("expected non-empty N and E in JWK")
		}
		if k.Kid == "" {
			t.Error("expected non-empty kid in JWK")
		}
	}
}

func TestJWKSDBErrorReturns500(t *testing.T) {
	setupTestDB(t)
	db.Close()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on db error, got %d", w.Code)
	}
}

func TestJWKSEmptyWhenNoValidKeys(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM keys WHERE exp > ?", time.Now().Unix())
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp JWKS
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(resp.Keys))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestClientIPFromRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	if ip := clientIP(req); ip != "1.2.3.4:5678" {
		t.Errorf("expected 1.2.3.4:5678, got %s", ip)
	}
}

func TestClientIPPrefersForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:9000"
	req.Header.Set("X-Forwarded-For", "9.8.7.6")
	if ip := clientIP(req); ip != "9.8.7.6" {
		t.Errorf("expected 9.8.7.6, got %s", ip)
	}
}

func TestLogAuthRequestBothPaths(t *testing.T) {
	setupTestDB(t)
	logAuthRequest("1.1.1.1:80", nil)
	id := 999
	logAuthRequest("2.2.2.2:80", &id)
}

func TestSetupRoutes(t *testing.T) {
	setupRoutes()
}

func TestRegisterAndAuthFullFlow(t *testing.T) {
	setupTestDB(t)
	limiter = newFixedWindowLimiter(100)

	regBody := `{"username":"flowuser","email":"flow@example.com"}`
	regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	registerHandler(regW, regReq)
	if regW.Code != http.StatusCreated {
		t.Fatalf("register failed: %d", regW.Code)
	}

	authBody := `{"username":"flowuser"}`
	authReq := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(authBody))
	authReq.Header.Set("Content-Type", "application/json")
	authReq.ContentLength = int64(len(authBody))
	authW := httptest.NewRecorder()
	authHandler(authW, authReq)
	if authW.Code != http.StatusOK {
		t.Errorf("auth failed: %d", authW.Code)
	}
	var resp map[string]string
	json.NewDecoder(authW.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("expected token in auth response")
	}
}

func TestOpenDatabaseInMemory(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	err := openDatabase(":memory:")
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if db == nil {
		t.Error("expected db to be set after openDatabase")
	}
	// Re-create tables so other tests still work
	createTables()
	seedKeys()
}

func TestSeedKeysCreatesKeysOnEmptyDB(t *testing.T) {
	os.Setenv("NOT_MY_KEY", testKey)
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	createTables()
	// DB is empty — seedKeys should generate both a valid and an expired key
	seedKeys()
	now := time.Now().Unix()
	var valid, expired int
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", now).Scan(&valid)
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now).Scan(&expired)
	if valid == 0 {
		t.Error("expected at least one valid key after seedKeys on empty DB")
	}
	if expired == 0 {
		t.Error("expected at least one expired key after seedKeys on empty DB")
	}
}

func TestGetKeyExpiredBranch(t *testing.T) {
	setupTestDB(t)
	// Explicitly test the expired=true branch of getKey
	kid, key, err := getKey(true)
	if err != nil {
		t.Fatalf("getKey(true): %v", err)
	}
	if key == nil {
		t.Error("expected non-nil key for expired branch")
	}
	if kid == 0 {
		t.Error("expected non-zero kid")
	}
}
