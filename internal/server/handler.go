package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/bayonos/backend-go/internal/auth"
)

type Handler struct {
	auth *auth.Service
}

func NewHandler(service *auth.Service) *Handler {
	return &Handler{auth: service}
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func writeJSON(w http.ResponseWriter, statusCode int, body any) {
	setCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, map[string]string{"error": message})
}

type authResponseBody struct {
	User         *auth.PublicUser `json:"user,omitempty"`
	AccessToken  string           `json:"access_token,omitempty"`
	RefreshToken string           `json:"refresh_token,omitempty"`
	TokenType    string           `json:"token_type,omitempty"`
	ExpiresIn    int              `json:"expires_in,omitempty"`
}

func writeAuthResult(w http.ResponseWriter, result auth.Result) {
	if !result.OK {
		writeError(w, result.StatusCode, result.Error)
		return
	}
	body := authResponseBody{User: result.User}
	if result.Tokens != nil {
		body.AccessToken = result.Tokens.AccessToken
		body.RefreshToken = result.Tokens.RefreshToken
		body.TokenType = result.Tokens.TokenType
		body.ExpiresIn = result.Tokens.ExpiresIn
	}
	writeJSON(w, result.StatusCode, body)
}

func parseJSONObject(r *http.Request) (map[string]any, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil || parsed == nil {
		return nil, false
	}
	return parsed, true
}

func getStringField(obj map[string]any, key string) (string, bool) {
	value, ok := obj[key].(string)
	return value, ok
}

func extractBearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

func extractClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
			return first
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return "127.0.0.1"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		setCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := r.Context()
	path := r.URL.Path

	if r.Method == http.MethodGet && path == "/" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "smartfarm-auth-backend",
			"endpoints": []string{
				"GET /health",
				"POST /api/auth/register",
				"POST /api/auth/login",
				"POST /api/auth/refresh",
				"POST /api/auth/logout",
				"POST /api/auth/logout-all",
				"GET /api/auth/me",
				"POST /api/auth/change-password",
			},
		})
		return
	}

	if r.Method == http.MethodGet && (path == "/health" || path == "/healthz") {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	if r.Method == http.MethodPost && (path == "/api/auth/register" || path == "/auth/register") {
		body, ok := parseJSONObject(r)
		if !ok {
			writeError(w, 400, "Invalid JSON request body")
			return
		}
		username, hasUsername := getStringField(body, "username")
		password, hasPassword := getStringField(body, "password")
		if !hasUsername || !hasPassword {
			writeError(w, 400, "username and password are required strings")
			return
		}
		fullName, hasFullName := getStringField(body, "full_name")
		if !hasFullName {
			fullName = username
		}
		email, _ := getStringField(body, "email")
		phone, _ := getStringField(body, "phone")
		role, _ := getStringField(body, "role")
		writeAuthResult(w, h.auth.RegisterUser(ctx, username, password, fullName, email, phone, role))
		return
	}

	if r.Method == http.MethodPost && (path == "/api/auth/login" || path == "/auth/login") {
		body, ok := parseJSONObject(r)
		if !ok {
			writeError(w, 400, "Invalid JSON request body")
			return
		}
		identifier, ok := getStringField(body, "identifier")
		if !ok {
			identifier, ok = getStringField(body, "email")
		}
		if !ok {
			identifier, ok = getStringField(body, "username")
		}
		password, hasPassword := getStringField(body, "password")
		if !ok || !hasPassword {
			writeError(w, 400, "username (or email/identifier) and password are required")
			return
		}
		writeAuthResult(w, h.auth.Login(ctx, identifier, password, extractClientIP(r)))
		return
	}

	if r.Method == http.MethodPost && (path == "/api/auth/refresh" || path == "/auth/refresh") {
		body, ok := parseJSONObject(r)
		if !ok {
			writeError(w, 400, "Invalid JSON request body")
			return
		}
		refreshToken, ok := getStringField(body, "refresh_token")
		if !ok {
			writeError(w, 400, "refresh_token is required")
			return
		}
		writeAuthResult(w, h.auth.RefreshSession(ctx, refreshToken))
		return
	}

	if r.Method == http.MethodPost && (path == "/api/auth/logout" || path == "/auth/logout") {
		body, ok := parseJSONObject(r)
		if !ok {
			writeError(w, 400, "Invalid JSON request body")
			return
		}
		refreshToken, ok := getStringField(body, "refresh_token")
		if !ok {
			writeError(w, 400, "refresh_token is required")
			return
		}
		if result := h.auth.Logout(ctx, refreshToken); !result.OK {
			writeError(w, result.StatusCode, result.Error)
			return
		}
		writeJSON(w, 200, map[string]string{"message": "Logged out"})
		return
	}

	if r.Method == http.MethodPost && (path == "/api/auth/logout-all" || path == "/auth/logout-all") {
		claims := h.auth.AuthenticateAccessToken(extractBearerToken(r))
		if extractBearerToken(r) == "" {
			writeError(w, 401, "Missing or invalid Authorization header")
			return
		}
		if claims == nil {
			writeError(w, 401, "Invalid or expired access token")
			return
		}
		h.auth.LogoutAll(ctx, claims.UserID)
		writeJSON(w, 200, map[string]string{"message": "All sessions revoked"})
		return
	}

	if r.Method == http.MethodGet && (path == "/api/auth/me" || path == "/auth/me") {
		if extractBearerToken(r) == "" {
			writeError(w, 401, "Missing or invalid Authorization header")
			return
		}
		claims := h.auth.AuthenticateAccessToken(extractBearerToken(r))
		if claims == nil {
			writeError(w, 401, "Invalid or expired access token")
			return
		}
		writeAuthResult(w, h.auth.GetProfile(ctx, claims.UserID))
		return
	}

	if r.Method == http.MethodPost && (path == "/api/auth/change-password" || path == "/auth/change-password") {
		if extractBearerToken(r) == "" {
			writeError(w, 401, "Missing or invalid Authorization header")
			return
		}
		claims := h.auth.AuthenticateAccessToken(extractBearerToken(r))
		if claims == nil {
			writeError(w, 401, "Invalid or expired access token")
			return
		}
		body, ok := parseJSONObject(r)
		if !ok {
			writeError(w, 400, "Invalid JSON request body")
			return
		}
		currentPassword, hasCurrent := getStringField(body, "current_password")
		newPassword, hasNew := getStringField(body, "new_password")
		if !hasCurrent || !hasNew {
			writeError(w, 400, "current_password and new_password are required")
			return
		}
		if result := h.auth.ChangePassword(ctx, claims.UserID, currentPassword, newPassword); !result.OK {
			writeError(w, result.StatusCode, result.Error)
			return
		}
		writeJSON(w, 200, map[string]string{"message": "Password updated; all refresh tokens revoked"})
		return
	}

	writeError(w, 404, "Not found")
}
