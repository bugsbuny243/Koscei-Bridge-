package main

import (
	"os"
	"strings"
	"testing"
)

func TestSharedDynamicProductCopyIsEnglish(t *testing.T) {
	files := map[string][]string{
		"public/js/koschei-product-v2.js": {
			"ARVIS production pipeline ready",
			"DEGRADED · production pipeline could not be verified",
			"DEGRADED · evidence service unavailable",
			"Health check did not respond within",
		},
		"public/js/feedback-button.js": {
			"Send feedback",
			"✦ Feedback",
		},
	}
	for path, required := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		for _, fragment := range required {
			if !strings.Contains(text, fragment) {
				t.Errorf("%s missing English dynamic copy %q", path, fragment)
			}
		}
		for _, forbidden := range []string{
			"evidence servisi erişilemiyor",
			"üretim hattı doğrulanamadı",
			"Sağlık kontrolü",
			"Geri bildirim gönder",
			"Geri Bildirim",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still produces Turkish dynamic copy %q", path, forbidden)
			}
		}
	}
}
