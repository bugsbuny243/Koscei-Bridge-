package main

import (
	"os"
	"strings"
	"testing"
)

func TestCoreCustomerSurfacesAreSourceEnglishWave2(t *testing.T) {
	files := map[string][]string{
		"public/index.html": {
			"The security layer beneath Web3",
			"See the execution.",
			"NO VALID PROOF = NO SIGNATURE",
			"visualization layer · not a synthetic live verdict",
			"A dashboard score is not an authorization primitive",
			"id=\"execution-proof\"",
		},
		"public/account.html": {
			"Account & SaaS Access",
			"Verify with Phantom",
			"Identity only.",
			"Current paid plan",
		},
		"public/reports.html": {
			"Investigation History",
			"History without invented evidence.",
			"SIGNED means the completed result explicitly carries",
		},
	}

	for path, required := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		if !strings.Contains(text, `<html lang="en">`) {
			t.Errorf("%s is not source-English", path)
		}
		for _, fragment := range required {
			if !strings.Contains(text, fragment) {
				t.Errorf("%s missing English contract %q", path, fragment)
			}
		}
		for _, forbidden := range []string{
			"Giriş Yap",
			"Hesap Oluştur",
			"Token Tara",
			"Ücretsiz kontrol et",
			"Rapor geçmişi yükleniyor",
			"Phantom ile Doğrula",
			"Çıkış Yap",
			"KAPSAM SINIRI",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still contains Turkish product copy %q", path, forbidden)
			}
		}
	}
}

func TestFrozenAuthSurfacesHaveEnglishPresentationOverlay(t *testing.T) {
	overlay, err := os.ReadFile("public/js/english-auth-presentation.js")
	if err != nil {
		t.Fatalf("read auth English presentation: %v", err)
	}
	text := string(overlay)
	for _, required := range []string{
		"'Giriş Yap':'Sign In'",
		"'Hesap Oluştur':'Create Account'",
		"'E-posta':'Email'",
		"'Şifre':'Password'",
		"'Giriş başarılı.':'Sign-in successful.'",
		"'Hesap oluşturuldu.':'Account created.'",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("auth English presentation missing %q", required)
		}
	}

	for _, path := range []string{"public/login.html", "public/register.html"} {
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read frozen auth surface %s: %v", path, readErr)
		}
		if !strings.Contains(string(body), "/js/koschei-auth.js?v=33") {
			t.Errorf("%s lost the frozen Neon-auth client contract", path)
		}
	}
}
