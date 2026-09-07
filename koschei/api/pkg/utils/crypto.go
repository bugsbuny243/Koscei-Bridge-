package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(salt, []byte(password)...))
	return fmt.Sprintf("$koschei-sha256$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum[:])), nil
}

func ComparePassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) == 4 && parts[1] == "koschei-sha256" {
		salt, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			return false
		}
		expected, err := base64.RawStdEncoding.DecodeString(parts[3])
		if err != nil {
			return false
		}
		sum := sha256.Sum256(append(salt, []byte(password)...))
		return subtle.ConstantTimeCompare(sum[:], expected) == 1
	}
	return false
}

func IsArgon2Hash(s string) bool {
	return strings.HasPrefix(s, "$argon2id$") || strings.HasPrefix(s, "$koschei-sha256$")
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
