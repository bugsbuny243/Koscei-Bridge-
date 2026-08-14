package utils

import (
	"strings"
	"testing"
)

func TestPasswordHashUsesArgon2id(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") || !IsArgon2Hash(hash) {
		t.Fatalf("unexpected password hash format: %q", hash)
	}
	if !ComparePassword(hash, "correct horse battery staple") {
		t.Fatal("correct password did not verify")
	}
	if ComparePassword(hash, "wrong password") {
		t.Fatal("wrong password verified")
	}
}

func TestPasswordHashRejectsLegacyAndHostileParameters(t *testing.T) {
	if ComparePassword("$koschei-sha256$c2FsdA$ZGlnaWVzdA", "password") {
		t.Fatal("legacy weak hash was accepted")
	}
	if ComparePassword("$argon2id$v=19$m=999999999,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$ZGlnaWVzdGRpZ2VzdGRpZ2VzdA", "password") {
		t.Fatal("hostile Argon2 parameters were accepted")
	}
}
