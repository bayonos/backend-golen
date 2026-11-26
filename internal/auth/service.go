package auth

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bayonos/backend-go/internal/config"
	"github.com/bayonos/backend-go/internal/crypto"
	"github.com/bayonos/backend-go/internal/store"
)

type PublicUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type Result struct {
	OK         bool
	StatusCode int
	Error      string
	User       *PublicUser
	Tokens     *Tokens
}

func fail(statusCode int, message string) Result {
	return Result{StatusCode: statusCode, Error: message}
}

func success(statusCode int) Result {
	return Result{OK: true, StatusCode: statusCode}
}

type RateLimiter struct {
	mu          sync.Mutex
	attempts    map[string][]int64
	maxAttempts int
	windowSec   int
}

func NewRateLimiter(maxAttempts, windowSec int) *RateLimiter {
	return &RateLimiter{
		attempts:    make(map[string][]int64),
		maxAttempts: maxAttempts,
		windowSec:   windowSec,
	}
}

func (r *RateLimiter) Allow(key string, nowEpochSec int64) bool {
	if r.maxAttempts <= 0 || r.windowSec <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	queue := r.attempts[key]
	cutoff := nowEpochSec - int64(r.windowSec)
	for len(queue) > 0 && queue[0] <= cutoff {
		queue = queue[1:]
	}
	if len(queue) >= r.maxAttempts {
		r.attempts[key] = queue
		return false
	}
	r.attempts[key] = append(queue, nowEpochSec)
	return true
}

var (
	usernameRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	emailRegex    = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	validRoles    = map[string]bool{"owner": true, "manager": true, "staff": true, "admin": true}
)

type Service struct {
	db        store.Database
	cfg       config.Config
	limiter   *RateLimiter
	dummyOnce sync.Once
	dummyHash string
}

func NewService(db store.Database, cfg config.Config) *Service {
	return &Service{
		db:      db,
		cfg:     cfg,
		limiter: NewRateLimiter(cfg.MaxLoginAttempts, cfg.RateLimitWindowSec),
	}
}

func NowEpochSeconds() int64 {
	return time.Now().Unix()
}

func (s *Service) dummyPasswordHash() string {
	s.dummyOnce.Do(func() {
		hash, err := crypto.HashPassword("timing-mitigation-placeholder", s.cfg.PBKDF2Iterations)
		if err == nil {
			s.dummyHash = hash
		}
	})
	return s.dummyHash
}

func normalizeLowerTrim(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isValidUsername(username string) bool {
	return len(username) >= 3 && len(username) <= 50 && usernameRegex.MatchString(username)
}

func isValidEmail(email string) bool {
	return len(email) >= 5 && len(email) <= 120 && emailRegex.MatchString(email)
}

func validatePassword(password string) string {
	if len(password) < 8 {
		return "Password must be at least 8 characters long"
	}
	if len(password) > 128 {
		return "Password must be at most 128 characters long"
	}
	hasLetter := false
	hasDigit := false
	for _, r := range password {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return "Password must include at least one letter and one number"
	}
	return ""
}

func verifyStoredPassword(candidate, stored string) bool {
	if strings.HasPrefix(stored, "pbkdf2_sha256$") {
		return crypto.VerifyPassword(candidate, stored)
	}
	return stored != "" && crypto.ConstantTimeEquals(candidate, stored)
}

func toPublicUser(user *store.User) *PublicUser {
	return &PublicUser{
		ID:        user.ID,
		Username:  user.Username,
		FullName:  user.FullName,
		Email:     user.Email,
		Phone:     user.Phone,
		Role:      user.Role,
		Status:    user.Status,
		CreatedAt: user.CreatedAt,
	}
}

func ignoreNoRows[T any](value *T, err error) (*T, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return value, err
}

func (s *Service) issueTokens(ctx context.Context, user *store.User, now int64) (*Tokens, error) {
	claims := crypto.Claims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		IssuedAt:  now,
		ExpiresAt: now + int64(s.cfg.AccessTokenTTLSec),
		JTI:       crypto.RandomHex(16),
	}
	accessToken := crypto.CreateJWT(claims, s.cfg.JWTSecret)
	refreshToken := crypto.RandomHex(32)
	err := s.db.StoreRefreshToken(ctx, user.ID, crypto.SHA256Hex(refreshToken),
		now+int64(s.cfg.RefreshTokenTTLSec), now)
	if err != nil {
		return nil, errors.New("Failed to store refresh token")
	}
	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.cfg.AccessTokenTTLSec,
	}, nil
}

func (s *Service) RegisterUser(ctx context.Context, username, password, fullName, email, phone, role string) Result {
	cleanUsername := strings.TrimSpace(username)
	cleanFullName := strings.TrimSpace(fullName)
	cleanEmail := normalizeLowerTrim(email)
	cleanPhone := strings.TrimSpace(phone)
	cleanRole := "owner"
	if role != "" {
		cleanRole = normalizeLowerTrim(role)
	}

	if !isValidUsername(cleanUsername) {
		return fail(400, "Username must be 3-50 characters (letters, digits, _, ., -)")
	}
	if cleanFullName == "" || len(cleanFullName) > 100 {
		return fail(400, "full_name is required (max 100 characters)")
	}
	if cleanEmail != "" && !isValidEmail(cleanEmail) {
		return fail(400, "Invalid email address")
	}
	if len(cleanPhone) > 30 {
		return fail(400, "phone must be at most 30 characters")
	}
	if !validRoles[cleanRole] {
		return fail(400, "role must be one of: owner, manager, staff, admin")
	}
	if message := validatePassword(password); message != "" {
		return fail(400, message)
	}

	if cleanEmail != "" {
		existing, err := ignoreNoRows(s.db.FindUserByEmail(ctx, cleanEmail))
		if err != nil {
			return fail(500, err.Error())
		}
		if existing != nil {
			return fail(409, "Email already exists")
		}
	}

	now := NowEpochSeconds()
	passwordHash, err := crypto.HashPassword(password, s.cfg.PBKDF2Iterations)
	if err != nil {
		return fail(500, err.Error())
	}
	created, err := s.db.CreateUser(ctx, cleanUsername, passwordHash, cleanFullName, cleanEmail, cleanPhone, cleanRole)
	if err != nil {
		return fail(409, err.Error())
	}

	tokens, err := s.issueTokens(ctx, created, now)
	if err != nil {
		return fail(500, err.Error())
	}
	result := success(201)
	result.User = toPublicUser(created)
	result.Tokens = tokens
	return result
}

func (s *Service) Login(ctx context.Context, identifier, password, clientIP string) Result {
	now := NowEpochSeconds()
	rateKey := clientIP
	if rateKey == "" {
		rateKey = "unknown"
	}
	if !s.limiter.Allow(rateKey, now) {
		return fail(429, "Too many login attempts. Please try again later.")
	}

	cleanID := strings.TrimSpace(identifier)
	if cleanID == "" || password == "" {
		return fail(400, "Identifier and password are required")
	}

	var (
		user *store.User
		err  error
	)
	if strings.Contains(cleanID, "@") {
		user, err = ignoreNoRows(s.db.FindUserByEmail(ctx, normalizeLowerTrim(cleanID)))
	} else {
		user, err = ignoreNoRows(s.db.FindUserByUsername(ctx, cleanID))
	}
	if err != nil {
		return fail(500, err.Error())
	}
	if user == nil {
		if hash := s.dummyPasswordHash(); hash != "" {
			crypto.VerifyPassword(password, hash)
		}
		return fail(401, "Invalid credentials")
	}
	if !verifyStoredPassword(password, user.Password) {
		return fail(401, "Invalid credentials")
	}
	if user.Status != "active" {
		return fail(403, "User account is inactive")
	}

	tokens, err := s.issueTokens(ctx, user, now)
	if err != nil {
		return fail(500, err.Error())
	}
	result := success(200)
	result.User = toPublicUser(user)
	result.Tokens = tokens
	return result
}

func (s *Service) RefreshSession(ctx context.Context, refreshToken string) Result {
	cleanToken := strings.TrimSpace(refreshToken)
	if cleanToken == "" {
		return fail(400, "refresh_token is required")
	}
	now := NowEpochSeconds()
	tokenHash := crypto.SHA256Hex(cleanToken)
	record, err := ignoreNoRows(s.db.FindRefreshToken(ctx, tokenHash))
	if err != nil {
		return fail(500, err.Error())
	}
	if record == nil || record.Revoked || record.ExpiresAt <= now {
		return fail(401, "Invalid or expired refresh token")
	}
	revoked, err := s.db.RevokeRefreshToken(ctx, tokenHash)
	if err != nil || !revoked {
		return fail(401, "Invalid or expired refresh token")
	}
	user, err := ignoreNoRows(s.db.FindUserByID(ctx, record.UserID))
	if err != nil {
		return fail(500, err.Error())
	}
	if user == nil {
		return fail(401, "User no longer exists")
	}
	if user.Status != "active" {
		return fail(403, "User account is inactive")
	}
	tokens, err := s.issueTokens(ctx, user, now)
	if err != nil {
		return fail(500, err.Error())
	}
	result := success(200)
	result.User = toPublicUser(user)
	result.Tokens = tokens
	return result
}

func (s *Service) Logout(ctx context.Context, refreshToken string) Result {
	cleanToken := strings.TrimSpace(refreshToken)
	if cleanToken == "" {
		return fail(400, "refresh_token is required")
	}
	s.db.RevokeRefreshToken(ctx, crypto.SHA256Hex(cleanToken))
	return success(200)
}

func (s *Service) LogoutAll(ctx context.Context, userID int64) Result {
	s.db.RevokeAllUserRefreshTokens(ctx, userID)
	return success(200)
}

func (s *Service) AuthenticateAccessToken(bearerToken string) *crypto.Claims {
	if bearerToken == "" {
		return nil
	}
	claims, err := crypto.VerifyJWT(bearerToken, s.cfg.JWTSecret, NowEpochSeconds())
	if err != nil {
		return nil
	}
	return claims
}

func (s *Service) GetProfile(ctx context.Context, userID int64) Result {
	user, err := ignoreNoRows(s.db.FindUserByID(ctx, userID))
	if err != nil {
		return fail(500, err.Error())
	}
	if user == nil {
		return fail(404, "User not found")
	}
	result := success(200)
	result.User = toPublicUser(user)
	return result
}

func (s *Service) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword string) Result {
	if currentPassword == "" || newPassword == "" {
		return fail(400, "current_password and new_password are required")
	}
	if message := validatePassword(newPassword); message != "" {
		return fail(400, message)
	}
	user, err := ignoreNoRows(s.db.FindUserByID(ctx, userID))
	if err != nil {
		return fail(500, err.Error())
	}
	if user == nil {
		return fail(404, "User not found")
	}
	if !verifyStoredPassword(currentPassword, user.Password) {
		return fail(401, "Current password is incorrect")
	}
	newHash, err := crypto.HashPassword(newPassword, s.cfg.PBKDF2Iterations)
	if err != nil {
		return fail(500, err.Error())
	}
	updated, err := s.db.UpdatePassword(ctx, userID, newHash)
	if err != nil || !updated {
		return fail(500, "Failed to update password")
	}
	s.db.RevokeAllUserRefreshTokens(ctx, userID)
	return success(200)
}
