package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
)

type Claims struct {
	UserID    int64  `json:"sub"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JTI       string `json:"jti"`
}

var base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9\-_]+={0,2}$`)

func RandomHex(numBytes int) string {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func SHA256Hex(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func ConstantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	const hLen = sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)

	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashPassword returns pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>.
func HashPassword(password string, iterations int) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	return "pbkdf2_sha256$" + strconv.Itoa(iterations) + "$" +
		hex.EncodeToString(salt) + "$" + hex.EncodeToString(derived), nil
}

func VerifyPassword(password, storedHash string) bool {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 || strconv.Itoa(iterations) != parts[1] {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil || len(expected) == 0 {
		return false
	}
	derived := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
	return hmac.Equal(derived, expected)
}

func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func Base64URLDecode(encoded string) ([]byte, error) {
	if encoded == "" {
		return []byte{}, nil
	}
	if !base64URLPattern.MatchString(encoded) {
		return nil, errors.New("invalid base64url")
	}
	trimmed := strings.TrimRight(encoded, "=")
	return base64.RawURLEncoding.DecodeString(trimmed)
}

func CreateJWT(claims Claims, secret string) string {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := Base64URLEncode(header) + "." + Base64URLEncode(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + Base64URLEncode(mac.Sum(nil))
}

func VerifyJWT(token, secret string, nowEpochSec int64) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("malformed token")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := Base64URLEncode(mac.Sum(nil))
	if !ConstantTimeEquals(parts[2], expectedSig) {
		return nil, errors.New("invalid signature")
	}

	headerBytes, err := Base64URLDecode(parts[0])
	if err != nil {
		return nil, err
	}
	payloadBytes, err := Base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if header["alg"] != "HS256" {
		return nil, errors.New("unsupported algorithm")
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}

	sub, ok := jsonInt(payload["sub"])
	if !ok {
		return nil, errors.New("invalid sub")
	}
	exp, ok := jsonInt(payload["exp"])
	if !ok {
		return nil, errors.New("invalid exp")
	}
	username, ok := payload["username"].(string)
	if !ok {
		return nil, errors.New("invalid username")
	}
	email, ok := payload["email"].(string)
	if !ok {
		return nil, errors.New("invalid email")
	}

	claims := &Claims{
		UserID:    sub,
		Username:  username,
		Email:     email,
		ExpiresAt: exp,
	}
	if role, ok := payload["role"].(string); ok {
		claims.Role = role
	}
	if iat, ok := jsonInt(payload["iat"]); ok {
		claims.IssuedAt = iat
	}
	if jti, ok := payload["jti"].(string); ok {
		claims.JTI = jti
	}

	if claims.UserID <= 0 || claims.ExpiresAt <= nowEpochSec {
		return nil, errors.New("expired or invalid token")
	}
	return claims, nil
}

func jsonInt(value any) (int64, bool) {
	f, ok := value.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	return int64(f), true
}
