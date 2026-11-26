package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bayonos/backend-go/internal/config"
	"github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

type User struct {
	ID        int64
	Username  string
	Password  string
	FullName  string
	Email     string
	Phone     string
	Role      string
	Status    string
	CreatedAt string
}

type RefreshToken struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt int64
	Revoked   bool
	CreatedAt int64
}

type Database interface {
	InitSchema(ctx context.Context) error
	CreateUser(ctx context.Context, username, passwordHash, fullName, email, phone, role string) (*User, error)
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	FindUserByUsername(ctx context.Context, username string) (*User, error)
	FindUserByID(ctx context.Context, userID int64) (*User, error)
	UpdatePassword(ctx context.Context, userID int64, newPasswordHash string) (bool, error)
	StoreRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt, nowEpochSec int64) error
	FindRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) (bool, error)
	RevokeAllUserRefreshTokens(ctx context.Context, userID int64) error
	Close() error
}

type SQLDatabase struct {
	db     *sql.DB
	driver string
}

func New(ctx context.Context, cfg config.Config) (*SQLDatabase, error) {
	var db *sql.DB
	var err error
	driver := "mysql"

	if cfg.DBDriver == "sqlite" {
		driver = "sqlite"
		dsn := cfg.DBPath
		db, err = sql.Open(driver, dsn)
		if err == nil && cfg.DBPath != ":memory:" && !strings.Contains(dsn, "?") {
			db.SetMaxOpenConns(8)
		}
		if err == nil && cfg.DBPath == ":memory:" {
			db.SetMaxOpenConns(1)
		}
	} else if cfg.DBDriver == "mysql" {
		mc := mysql.NewConfig()
		mc.User = cfg.MySQLUser
		mc.Passwd = cfg.MySQLPassword
		mc.Net = "tcp"
		mc.Addr = fmt.Sprintf("%s:%d", cfg.MySQLHost, cfg.MySQLPort)
		mc.DBName = cfg.MySQLDatabase
		mc.Params = map[string]string{"charset": "utf8mb4"}
		db, err = sql.Open(driver, mc.FormatDSN())
	} else {
		return nil, fmt.Errorf("unsupported DB_DRIVER: %s (expected mysql or sqlite)", cfg.DBDriver)
	}
	if err != nil {
		return nil, err
	}

	if driver == "sqlite" {
		if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000;"); err != nil {
			db.Close()
			return nil, err
		}
		if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON;"); err != nil {
			db.Close()
			return nil, err
		}
		if cfg.DBPath != ":memory:" {
			if _, err := db.ExecContext(ctx, "PRAGMA journal_mode = WAL;"); err != nil {
				db.Close()
				return nil, err
			}
		}
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLDatabase{db: db, driver: driver}, nil
}

func (s *SQLDatabase) InitSchema(ctx context.Context) error {
	var statements []string
	if s.driver == "sqlite" {
		statements = []string{
			`CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL UNIQUE COLLATE NOCASE,
				password TEXT NOT NULL,
				full_name TEXT NOT NULL,
				email TEXT COLLATE NOCASE,
				phone TEXT,
				role TEXT NOT NULL DEFAULT 'owner',
				status TEXT NOT NULL DEFAULT 'active',
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS refresh_tokens (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				token_hash TEXT NOT NULL UNIQUE,
				expires_at INTEGER NOT NULL,
				revoked INTEGER NOT NULL DEFAULT 0,
				created_at INTEGER NOT NULL,
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
			)`,
			`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)`,
			`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)`,
		}
	} else {
		statements = []string{
			`CREATE TABLE IF NOT EXISTS users (
				id INT NOT NULL AUTO_INCREMENT,
				username VARCHAR(50) NOT NULL,
				password VARCHAR(255) NOT NULL,
				full_name VARCHAR(100) NOT NULL,
				email VARCHAR(120) DEFAULT NULL,
				phone VARCHAR(30) DEFAULT NULL,
				role ENUM('owner','manager','staff','admin') NOT NULL DEFAULT 'owner',
				status ENUM('active','inactive') NOT NULL DEFAULT 'active',
				created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (id),
				UNIQUE KEY username (username)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
			`CREATE TABLE IF NOT EXISTS refresh_tokens (
				id BIGINT NOT NULL AUTO_INCREMENT,
				user_id INT NOT NULL,
				token_hash CHAR(64) NOT NULL,
				expires_at BIGINT NOT NULL,
				revoked TINYINT(1) NOT NULL DEFAULT 0,
				created_at BIGINT NOT NULL,
				PRIMARY KEY (id),
				UNIQUE KEY uk_refresh_tokens_hash (token_hash),
				KEY idx_refresh_tokens_user_id (user_id),
				CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
					REFERENCES users(id) ON DELETE CASCADE
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		}
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var u User
	var email, phone, createdAt sql.NullString
	err := row.Scan(&u.ID, &u.Username, &u.Password, &u.FullName, &email, &phone, &u.Role, &u.Status, &createdAt)
	if err != nil {
		return nil, err
	}
	u.Email = email.String
	u.Phone = phone.String
	u.CreatedAt = createdAt.String
	return &u, nil
}

func (s *SQLDatabase) userQuery() string {
	if s.driver == "mysql" {
		return `SELECT id, username, password, full_name, email, phone, role, status,
			COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') AS created_at
			FROM users`
	}
	return `SELECT id, username, password, full_name, email, phone, role, status, created_at FROM users`
}

func isDuplicateEntry(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "Duplicate entry")
}

func (s *SQLDatabase) CreateUser(ctx context.Context, username, passwordHash, fullName, email, phone, role string) (*User, error) {
	createdAt := currentTimestampUTC()
	query := `INSERT INTO users (username, password, full_name, email, phone, role, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
	var emailArg, phoneArg any
	if email != "" {
		emailArg = email
	}
	if phone != "" {
		phoneArg = phone
	}
	result, err := s.db.ExecContext(ctx, query, username, passwordHash, fullName, emailArg, phoneArg, role, createdAt)
	if err != nil {
		if isDuplicateEntry(err) {
			return nil, errors.New("Username already exists")
		}
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 {
		return s.FindUserByUsername(ctx, username)
	}
	user, err := s.FindUserByID(ctx, id)
	if err == nil && user != nil {
		return user, nil
	}
	return s.FindUserByUsername(ctx, username)
}

func currentTimestampUTC() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

func (s *SQLDatabase) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.userQuery()+" WHERE LOWER(email) = LOWER(?) LIMIT 1", email))
}

func (s *SQLDatabase) FindUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.userQuery()+" WHERE LOWER(username) = LOWER(?) LIMIT 1", username))
}

func (s *SQLDatabase) FindUserByID(ctx context.Context, userID int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.userQuery()+" WHERE id = ? LIMIT 1", userID))
}

func (s *SQLDatabase) UpdatePassword(ctx context.Context, userID int64, newPasswordHash string) (bool, error) {
	result, err := s.db.ExecContext(ctx, "UPDATE users SET password = ? WHERE id = ?", newPasswordHash, userID)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return err == nil && affected > 0, err
}

func (s *SQLDatabase) StoreRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt, nowEpochSec int64) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)",
		userID, tokenHash, expiresAt, nowEpochSec)
	return err
}

func (s *SQLDatabase) FindRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var record RefreshToken
	var revoked int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, revoked, created_at
		 FROM refresh_tokens WHERE token_hash = ? LIMIT 1`, tokenHash,
	).Scan(&record.ID, &record.UserID, &record.TokenHash, &record.ExpiresAt, &revoked, &record.CreatedAt)
	if err != nil {
		return nil, err
	}
	record.Revoked = revoked != 0
	return &record, nil
}

func (s *SQLDatabase) RevokeRefreshToken(ctx context.Context, tokenHash string) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0", tokenHash)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return err == nil && affected > 0, err
}

func (s *SQLDatabase) RevokeAllUserRefreshTokens(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0", userID)
	return err
}

func (s *SQLDatabase) Close() error {
	return s.db.Close()
}
