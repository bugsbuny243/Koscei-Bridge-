package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time        = uint32(3)
	argon2Memory      = uint32(64 * 1024)
	argon2SaltLength  = 16
	argon2KeyLength   = uint32(32)
	maxArgon2Time     = uint32(10)
	maxArgon2Memory   = uint32(256 * 1024)
	maxArgon2Parallel = uint8(8)
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	parallelism := uint8(runtime.GOMAXPROCS(0))
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > 4 {
		parallelism = 4
	}
	derived := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, parallelism, argon2KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Time,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	), nil
}

func ComparePassword(encodedHash, password string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	if memory < 8*1024 || memory > maxArgon2Memory || iterations < 1 || iterations > maxArgon2Time || parallelism < 1 || parallelism > maxArgon2Parallel {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func IsArgon2Hash(s string) bool {
	return strings.HasPrefix(s, "$argon2id$v=")
}

// GetWalletFromJWT extracts a wallet/public-address claim from a JWT payload.
// It intentionally does not verify signatures; callers must verify the token
// before trusting the returned wallet for authorization decisions.
func GetWalletFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token is not a jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	for _, key := range []string{"wallet", "wallet_address", "public_address", "address"} {
		if wallet, ok := claims[key].(string); ok && strings.TrimSpace(wallet) != "" {
			return strings.TrimSpace(wallet), nil
		}
	}
	return "", fmt.Errorf("wallet claim not found")
}
