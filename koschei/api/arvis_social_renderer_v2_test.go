package main

import (
	"os"
	"strings"
	"testing"
)

func TestARVISSocialRendererV2Contract(t *testing.T) {
	files := map[string][]string{
		"public/js/arvis-social-render-v2-core.js": {
			"CRITICAL CONCENTRATION",
			"CLASSIC SPL",
			"TOKEN-2022 NOT APPLICABLE",
			"NO CLAIM FROM MISSING DATA",
		},
		"public/js/arvis-social-render-v2-cards.js": {
			"HOLDER CONTROL",
			"EXIT LIQUIDITY",
			"LINKAGE & COVERAGE",
			"READ THE FULL SIGNED EVIDENCE",
		},
		"public/js/arvis-social-render-v2-publish.js": {
			"classic SPL token program",
			"bounded window; this does not rule out older activity",
			"socialRendererVersion='2.0.0'",
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
				t.Errorf("%s missing %q", path, fragment)
			}
		}
	}

	for _, path := range []string{
		"public/js/arvis-social-render-v2-core.js",
		"public/js/arvis-social-render-v2-cards.js",
		"public/js/arvis-social-render-v2-publish.js",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		for _, forbidden := range []string{
			"0 Token-2022 extension(s) parsed",
			"0 creator-linked token record(s)",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains misleading zero-state copy %q", path, forbidden)
			}
		}
	}
}
