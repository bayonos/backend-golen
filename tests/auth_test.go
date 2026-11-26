package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bayonos/backend-go/internal/auth"
	"github.com/bayonos/backend-go/internal/config"
	"github.com/bayonos/backend-go/internal/crypto"
	"github.com/bayonos/backend-go/internal/server"
	"github.com/bayonos/backend-go/internal/store"
)

func newTestDB(t *testing.T) (store.Database, config.Config) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.DBDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "auth.db")
	cfg.JWTSecret = "test-super-secret-key-at-least-32-bytes"
	cfg.AccessTokenTTLSec = 900
	cfg.RefreshTokenTTLSec = 3600
	cfg.PBKDF2Iterations = 10000
	cfg.MaxLoginAttempts = 3
	cfg.RateLimitWindowSec = 60

	db, err := store.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.InitSchema(context.Background()); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, cfg
}

func requireStatus(t *testing.T, result auth.Result, want int) {
	t.Helper()
	if result.StatusCode != want {
		t.Fatalf("status = %d, want %d (error: %q)", result.StatusCode, want, result.Error)
	}
}

func decodeJSON[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return value
}

func dispatch(handler http.Handler, method, path, body, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestConfigEnvParsing(t *testing.T) {
	cfg := config.DefaultConfig()
	config.ApplyDatabaseURL(
		"mysql://smartuser:pass%40word@bayonos-db-smartfarm:3307/smartfarm_db?ssl-mode=PREFERRED",
		&cfg,
	)
	if cfg.DBDriver != "mysql" || cfg.MySQLUser != "smartuser" ||
		cfg.MySQLPassword != "pass@word" || cfg.MySQLHost != "bayonos-db-smartfarm" ||
		cfg.MySQLPort != 3307 || cfg.MySQLDatabase != "smartfarm_db" {
		t.Fatalf("DATABASE_URL parsing failed: %+v", cfg)
	}

	envCfg := config.LoadConfig(map[string]string{
		"DB_CONNECTION": "mysql",
		"DB_HOST":       "db.internal",
		"DB_PORT":       "3308",
		"DB_USERNAME":   "appuser",
		"DB_PASSWORD":   "appsecret",
		"DB_DATABASE":   "smartfarm_db",
	}, "")
	if envCfg.DBDriver != "mysql" || envCfg.MySQLHost != "db.internal" ||
		envCfg.MySQLPort != 3308 || envCfg.MySQLUser != "appuser" ||
		envCfg.MySQLPassword != "appsecret" || envCfg.MySQLDatabase != "smartfarm_db" {
		t.Fatalf("DB_* env parsing failed: %+v", envCfg)
	}
}

func TestCrypto(t *testing.T) {
	raw := "hello+world/test=123"
	encoded := crypto.Base64URLEncode([]byte(raw))
	decoded, err := crypto.Base64URLDecode(encoded)
	if err != nil || string(decoded) != raw {
		t.Fatalf("base64url round trip failed: %q %v", decoded, err)
	}

	hash, err := crypto.HashPassword("SecretPass123", 10000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "pbkdf2_sha256$10000$") {
		t.Fatalf("unexpected hash format: %q", hash)
	}
	if !crypto.VerifyPassword("SecretPass123", hash) {
		t.Fatal("valid password rejected")
	}
	if crypto.VerifyPassword("WrongPass123", hash) {
		t.Fatal("invalid password accepted")
	}
	if crypto.VerifyPassword("SecretPass123", "malformed") {
		t.Fatal("malformed hash accepted")
	}

	now := auth.NowEpochSeconds()
	token := crypto.CreateJWT(crypto.Claims{
		UserID:    42,
		Username:  "alice",
		Email:     "alice@example.com",
		Role:      "owner",
		IssuedAt:  now,
		ExpiresAt: now + 300,
		JTI:       "jti-1",
	}, "secret-key")

	claims, err := crypto.VerifyJWT(token, "secret-key", now)
	if err != nil || claims.UserID != 42 || claims.Username != "alice" ||
		claims.Email != "alice@example.com" || claims.Role != "owner" {
		t.Fatalf("jwt verify failed: %+v %v", claims, err)
	}
	if _, err := crypto.VerifyJWT(token, "wrong-secret", now); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := crypto.VerifyJWT(token, "secret-key", now+301); err == nil {
		t.Fatal("expired token accepted")
	}
	last := token[len(token)-1]
	tampered := token[:len(token)-1]
	if last == 'a' {
		tampered += "b"
	} else {
		tampered += "a"
	}
	if _, err := crypto.VerifyJWT(tampered, "secret-key", now); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestServiceRegisterLoginRefreshLogout(t *testing.T) {
	ctx := context.Background()
	db, cfg := newTestDB(t)
	service := auth.NewService(db, cfg)

	cases := []struct {
		username, password, fullName, email, role string
	}{
		{"ab", "Password123", "Alice", "a@example.com", "owner"},
		{"alice", "Password123", "", "a@example.com", "owner"},
		{"alice", "Password123", "Alice", "bad-email", "owner"},
		{"alice", "short1", "Alice", "alice@example.com", "owner"},
		{"alice", "onlyletters", "Alice", "alice@example.com", "owner"},
		{"alice", "Password123", "Alice", "alice@example.com", "invalidrole"},
	}
	for _, tc := range cases {
		requireStatus(t, service.RegisterUser(ctx, tc.username, tc.password, tc.fullName, tc.email, "", tc.role), 400)
	}

	reg := service.RegisterUser(ctx, "alice", "Password123", "Alice Chan", "Alice@Example.com", "010290240", "manager")
	requireStatus(t, reg, 201)
	if !reg.OK || reg.User.Email != "alice@example.com" || reg.User.FullName != "Alice Chan" ||
		reg.User.Phone != "010290240" || reg.User.Role != "manager" || reg.User.Status != "active" || reg.Tokens == nil {
		t.Fatalf("unexpected registration: %+v", reg)
	}

	requireStatus(t, service.RegisterUser(ctx, "alice2", "Password123", "Alice Two", "alice@example.com", "", "owner"), 409)
	requireStatus(t, service.RegisterUser(ctx, "ALICE", "Password123", "Alice Dup", "alice2@example.com", "", "owner"), 409)

	claims := service.AuthenticateAccessToken(reg.Tokens.AccessToken)
	if claims == nil || claims.UserID != reg.User.ID || claims.Role != "manager" {
		t.Fatalf("access token authentication failed: %+v", claims)
	}
	profile := service.GetProfile(ctx, claims.UserID)
	requireStatus(t, profile, 200)
	if profile.User.Username != "alice" {
		t.Fatalf("unexpected profile: %+v", profile.User)
	}

	loginEmail := service.Login(ctx, "ALICE@example.com", "Password123", "127.0.0.1")
	requireStatus(t, loginEmail, 200)
	loginUser := service.Login(ctx, "alice", "Password123", "127.0.0.2")
	requireStatus(t, loginUser, 200)
	requireStatus(t, service.Login(ctx, "alice@example.com", "WrongPass123", "127.0.0.3"), 401)

	oldRefresh := loginEmail.Tokens.RefreshToken
	refreshed := service.RefreshSession(ctx, oldRefresh)
	requireStatus(t, refreshed, 200)
	if refreshed.Tokens.RefreshToken == oldRefresh {
		t.Fatal("refresh token was not rotated")
	}
	requireStatus(t, service.RefreshSession(ctx, oldRefresh), 401)
	requireStatus(t, service.Logout(ctx, refreshed.Tokens.RefreshToken), 200)
	requireStatus(t, service.RefreshSession(ctx, refreshed.Tokens.RefreshToken), 401)
}

func TestServiceLegacyPasswordRateLimitAndChangePassword(t *testing.T) {
	ctx := context.Background()
	db, cfg := newTestDB(t)
	service := auth.NewService(db, cfg)

	seeded, err := db.CreateUser(ctx, "admin", "admin123", "Raksmey Chann", "admin@efarm.local", "010290240", "owner")
	if err != nil || seeded == nil {
		t.Fatalf("seed user: %v", err)
	}
	loginSeed := service.Login(ctx, "admin", "admin123", "10.0.0.1")
	requireStatus(t, loginSeed, 200)
	if loginSeed.User.FullName != "Raksmey Chann" || loginSeed.User.Role != "owner" {
		t.Fatalf("unexpected seeded user: %+v", loginSeed.User)
	}

	requireStatus(t, service.Login(ctx, "admin", "Wrong1", "10.0.0.5"), 401)
	requireStatus(t, service.Login(ctx, "admin", "Wrong2", "10.0.0.5"), 401)
	requireStatus(t, service.Login(ctx, "admin", "Wrong3", "10.0.0.5"), 401)
	requireStatus(t, service.Login(ctx, "admin", "admin123", "10.0.0.5"), 429)

	refreshToken := loginSeed.Tokens.RefreshToken
	requireStatus(t, service.ChangePassword(ctx, seeded.ID, "WrongCurrent1", "NewPass123"), 401)
	requireStatus(t, service.ChangePassword(ctx, seeded.ID, "admin123", "NewPass123"), 200)
	requireStatus(t, service.RefreshSession(ctx, refreshToken), 401)
	requireStatus(t, service.Login(ctx, "admin", "admin123", "10.0.0.6"), 401)
	requireStatus(t, service.Login(ctx, "admin", "NewPass123", "10.0.0.6"), 200)
}

func TestHTTPRoutes(t *testing.T) {
	db, cfg := newTestDB(t)
	handler := server.NewHandler(auth.NewService(db, cfg))

	preflight := dispatch(handler, http.MethodOptions, "/api/auth/login", "", "")
	if preflight.Code != 204 || preflight.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("bad preflight: %d %v", preflight.Code, preflight.Header())
	}

	root := dispatch(handler, http.MethodGet, "/", "", "")
	if root.Code != 200 {
		t.Fatalf("root: %d", root.Code)
	}
	if value := decodeJSON[struct{ Status string }](t, root); value.Status != "ok" {
		t.Fatalf("root body: %+v", value)
	}

	health := dispatch(handler, http.MethodGet, "/health", "", "")
	if health.Code != 200 {
		t.Fatalf("health: %d", health.Code)
	}
	if value := decodeJSON[struct{ Status string }](t, health); value.Status != "ok" {
		t.Fatalf("health body: %+v", value)
	}

	if recorder := dispatch(handler, http.MethodPost, "/api/auth/register", "{bad", ""); recorder.Code != 400 {
		t.Fatalf("invalid JSON: %d", recorder.Code)
	}

	registration := dispatch(handler, http.MethodPost, "/api/auth/register", `{
		"username":"httpuser","password":"Password123","full_name":"HTTP User",
		"email":"http@example.com","phone":"012345678","role":"staff"}`, "")
	if registration.Code != 201 {
		t.Fatalf("register: %d %s", registration.Code, registration.Body.String())
	}
	registered := decodeJSON[struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		User         struct {
			FullName string `json:"full_name"`
			Role     string `json:"role"`
		} `json:"user"`
	}](t, registration)
	if registered.AccessToken == "" || registered.RefreshToken == "" ||
		registered.User.FullName != "HTTP User" || registered.User.Role != "staff" {
		t.Fatalf("unexpected registration body: %+v", registered)
	}

	loginAlias := dispatch(handler, http.MethodPost, "/auth/login",
		`{"email":"http@example.com","password":"Password123"}`, "")
	if loginAlias.Code != 200 {
		t.Fatalf("login alias: %d", loginAlias.Code)
	}
	login := dispatch(handler, http.MethodPost, "/api/auth/login",
		`{"email":"http@example.com","password":"Password123"}`, "")
	if login.Code != 200 {
		t.Fatalf("login: %d", login.Code)
	}
	loggedIn := decodeJSON[struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}](t, login)

	if recorder := dispatch(handler, http.MethodGet, "/api/auth/me", "", ""); recorder.Code != 401 {
		t.Fatalf("unauthenticated /me: %d", recorder.Code)
	}
	me := dispatch(handler, http.MethodGet, "/api/auth/me", "", "Bearer "+loggedIn.AccessToken)
	if me.Code != 200 {
		t.Fatalf("authenticated /me: %d", me.Code)
	}
	meBody := decodeJSON[struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}](t, me)
	if meBody.User.Username != "httpuser" {
		t.Fatalf("unexpected /me body: %+v", meBody)
	}

	refreshed := dispatch(handler, http.MethodPost, "/api/auth/refresh",
		`{"refresh_token":"`+loggedIn.RefreshToken+`"}`, "")
	if refreshed.Code != 200 {
		t.Fatalf("refresh: %d", refreshed.Code)
	}
	refreshedBody := decodeJSON[struct {
		RefreshToken string `json:"refresh_token"`
	}](t, refreshed)
	if refreshedBody.RefreshToken == loggedIn.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}

	changed := dispatch(handler, http.MethodPost, "/api/auth/change-password",
		`{"current_password":"Password123","new_password":"NewPassword456"}`, "Bearer "+loggedIn.AccessToken)
	if changed.Code != 200 {
		t.Fatalf("change password: %d %s", changed.Code, changed.Body.String())
	}

	afterChange := dispatch(handler, http.MethodPost, "/api/auth/refresh",
		`{"refresh_token":"`+refreshedBody.RefreshToken+`"}`, "")
	if afterChange.Code != 401 {
		t.Fatalf("refresh after password change: %d", afterChange.Code)
	}

	login2 := dispatch(handler, http.MethodPost, "/api/auth/login",
		`{"username":"httpuser","password":"NewPassword456"}`, "")
	if login2.Code != 200 {
		t.Fatalf("login with new password: %d", login2.Code)
	}
	login2Body := decodeJSON[struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}](t, login2)

	logoutAll := dispatch(handler, http.MethodPost, "/api/auth/logout-all", "", "Bearer "+login2Body.AccessToken)
	if logoutAll.Code != 200 {
		t.Fatalf("logout-all: %d", logoutAll.Code)
	}
	afterLogoutAll := dispatch(handler, http.MethodPost, "/api/auth/refresh",
		`{"refresh_token":"`+login2Body.RefreshToken+`"}`, "")
	if afterLogoutAll.Code != 401 {
		t.Fatalf("refresh after logout-all: %d", afterLogoutAll.Code)
	}

	if recorder := dispatch(handler, http.MethodGet, "/nope", "", ""); recorder.Code != 404 {
		t.Fatalf("unknown route: %d", recorder.Code)
	}
}
