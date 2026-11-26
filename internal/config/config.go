package config

import (
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/bayonos/backend-go/internal/crypto"
)

type Config struct {
	Host string
	Port int

	DBDriver string
	DBPath   string

	MySQLHost     string
	MySQLPort     int
	MySQLUser     string
	MySQLPassword string
	MySQLDatabase string

	JWTSecret            string
	JWTSecretIsEphemeral bool
	AccessTokenTTLSec    int
	RefreshTokenTTLSec   int
	PBKDF2Iterations     int
	MaxLoginAttempts     int
	RateLimitWindowSec   int
}

func DefaultConfig() Config {
	return Config{
		Host:               "0.0.0.0",
		Port:               8080,
		DBDriver:           "mysql",
		DBPath:             "auth.db",
		MySQLHost:          "127.0.0.1",
		MySQLPort:          3306,
		MySQLUser:          "root",
		MySQLPassword:      "root",
		MySQLDatabase:      "smartfarm_db",
		AccessTokenTTLSec:  900,
		RefreshTokenTTLSec: 604800,
		PBKDF2Iterations:   210000,
		MaxLoginAttempts:   10,
		RateLimitWindowSec: 60,
	}
}

func loadDotEnvIfPresent(path string, env map[string]string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if len(value) >= 2 &&
			((strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
				(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"))) {
			value = value[1 : len(value)-1]
		}
		if key != "" {
			if _, exists := env[key]; !exists {
				env[key] = value
			}
		}
	}
}

func safeDecode(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func ApplyDatabaseURL(rawURL string, cfg *Config) {
	if rawURL == "" {
		return
	}
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd == -1 {
		return
	}
	scheme := strings.ToLower(rawURL[:schemeEnd])
	rest := rawURL[schemeEnd+3:]

	if scheme == "sqlite" || scheme == "sqlite3" {
		cfg.DBDriver = "sqlite"
		if rest != "" {
			cfg.DBPath = rest
		}
		return
	}
	if scheme != "mysql" && scheme != "mysql2" && scheme != "mariadb" {
		return
	}
	cfg.DBDriver = "mysql"

	if qPos := strings.Index(rest, "?"); qPos != -1 {
		rest = rest[:qPos]
	}

	authority := rest
	if slashPos := strings.Index(rest, "/"); slashPos != -1 {
		authority = rest[:slashPos]
		if dbName := rest[slashPos+1:]; dbName != "" {
			cfg.MySQLDatabase = safeDecode(dbName)
		}
	}

	hostPort := authority
	if atPos := strings.LastIndex(authority, "@"); atPos != -1 {
		userInfo := authority[:atPos]
		hostPort = authority[atPos+1:]
		if colonPos := strings.Index(userInfo, ":"); colonPos != -1 {
			cfg.MySQLUser = safeDecode(userInfo[:colonPos])
			cfg.MySQLPassword = safeDecode(userInfo[colonPos+1:])
		} else if userInfo != "" {
			cfg.MySQLUser = safeDecode(userInfo)
		}
	}

	if hostPort != "" {
		if colonPos := strings.LastIndex(hostPort, ":"); colonPos != -1 {
			hostPart := hostPort[:colonPos]
			portPart := hostPort[colonPos+1:]
			if hostPart != "" {
				cfg.MySQLHost = hostPart
			}
			if parsed, err := strconv.Atoi(portPart); err == nil && parsed > 0 && parsed <= 65535 {
				cfg.MySQLPort = parsed
			}
		} else {
			cfg.MySQLHost = hostPort
		}
	}
}

func getEnvOrDefault(env map[string]string, name, fallback string) string {
	if val := env[name]; val != "" {
		return val
	}
	return fallback
}

func getFirstEnvOrDefault(env map[string]string, names []string, fallback string) string {
	for _, name := range names {
		if val := env[name]; val != "" {
			return val
		}
	}
	return fallback
}

func parseIntValue(val string) (int, bool) {
	f, err := strconv.ParseFloat(val, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

func getEnvIntOrDefault(env map[string]string, name string, fallback int) int {
	if val := env[name]; val != "" {
		if parsed, ok := parseIntValue(val); ok {
			return parsed
		}
	}
	return fallback
}

func getFirstEnvIntOrDefault(env map[string]string, names []string, fallback int) int {
	for _, name := range names {
		if val := env[name]; val != "" {
			if parsed, ok := parseIntValue(val); ok {
				return parsed
			}
		}
	}
	return fallback
}

// LoadConfig builds a Config from the supplied environment. Values in env take
// precedence over entries in dotEnvPath, matching BunJS behaviour.
func LoadConfig(env map[string]string, dotEnvPath string) Config {
	merged := make(map[string]string, len(env)+8)
	for key, value := range env {
		merged[key] = value
	}
	if dotEnvPath != "" {
		loadDotEnvIfPresent(dotEnvPath, merged)
	}

	cfg := DefaultConfig()
	cfg.Host = getEnvOrDefault(merged, "HOST", cfg.Host)
	if port := getEnvIntOrDefault(merged, "PORT", cfg.Port); port > 0 && port <= 65535 {
		cfg.Port = port
	}

	if databaseURL := getEnvOrDefault(merged, "DATABASE_URL", ""); databaseURL != "" {
		ApplyDatabaseURL(databaseURL, &cfg)
	}

	cfg.DBDriver = getFirstEnvOrDefault(merged, []string{"DB_DRIVER", "DB_CONNECTION"}, cfg.DBDriver)
	cfg.DBPath = getEnvOrDefault(merged, "DB_PATH", cfg.DBPath)
	cfg.MySQLHost = getFirstEnvOrDefault(merged, []string{"MYSQL_HOST", "DB_HOST"}, cfg.MySQLHost)
	if port := getFirstEnvIntOrDefault(merged, []string{"MYSQL_PORT", "DB_PORT"}, cfg.MySQLPort); port > 0 && port <= 65535 {
		cfg.MySQLPort = port
	}
	cfg.MySQLUser = getFirstEnvOrDefault(merged, []string{"MYSQL_USER", "DB_USER", "DB_USERNAME"}, cfg.MySQLUser)
	cfg.MySQLPassword = getFirstEnvOrDefault(merged, []string{"MYSQL_PASSWORD", "DB_PASSWORD"}, cfg.MySQLPassword)
	cfg.MySQLDatabase = getFirstEnvOrDefault(merged, []string{"MYSQL_DB", "DB_DATABASE", "DB_NAME"}, cfg.MySQLDatabase)

	cfg.JWTSecret = getEnvOrDefault(merged, "JWT_SECRET", "")
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = crypto.RandomHex(32)
		cfg.JWTSecretIsEphemeral = true
	}
	if ttl := getEnvIntOrDefault(merged, "ACCESS_TOKEN_TTL_SEC", cfg.AccessTokenTTLSec); ttl > 0 {
		cfg.AccessTokenTTLSec = ttl
	}
	if ttl := getEnvIntOrDefault(merged, "REFRESH_TOKEN_TTL_SEC", cfg.RefreshTokenTTLSec); ttl > 0 {
		cfg.RefreshTokenTTLSec = ttl
	}
	if iterations := getEnvIntOrDefault(merged, "PBKDF2_ITERATIONS", cfg.PBKDF2Iterations); iterations >= 10000 {
		cfg.PBKDF2Iterations = iterations
	}
	if attempts := getEnvIntOrDefault(merged, "LOGIN_MAX_ATTEMPTS", cfg.MaxLoginAttempts); attempts > 0 {
		cfg.MaxLoginAttempts = attempts
	}
	if window := getEnvIntOrDefault(merged, "LOGIN_RATE_WINDOW_SEC", cfg.RateLimitWindowSec); window > 0 {
		cfg.RateLimitWindowSec = window
	}
	return cfg
}

func Environ() map[string]string {
	env := make(map[string]string)
	for _, entry := range os.Environ() {
		if idx := strings.Index(entry, "="); idx != -1 {
			env[entry[:idx]] = entry[idx+1:]
		}
	}
	return env
}
