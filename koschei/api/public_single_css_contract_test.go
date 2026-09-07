package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var internalPublicStylesheetRE = regexp.MustCompile(`(?i)<link\b[^>]*\brel=["']stylesheet["'][^>]*\bhref=["'](/css/[^"']+\.css(?:\?[^"']*)?)["'][^>]*>`)

func TestPublicSiteKeepsTwoPrimaryStylesAndOneLegacyCompatibilityBundle(t *testing.T) {
	files, err := filepath.Glob("public/css/*.css")
	if err != nil {
		t.Fatalf("glob public css: %v", err)
	}
	sort.Strings(files)
	want := []string{
		filepath.FromSlash("public/css/koschei-dashboard.css"),
		filepath.FromSlash("public/css/koschei-home.css"),
		filepath.FromSlash("public/css/koschei.css"),
	}
	if len(files) != len(want) {
		t.Fatalf("public CSS contract drifted: got %v, want %v", files, want)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Fatalf("public CSS contract drifted: got %v, want %v", files, want)
		}
	}

	legacyBundle, err := os.ReadFile(filepath.FromSlash("public/css/koschei.css"))
	if err != nil {
		t.Fatalf("read legacy compatibility CSS: %v", err)
	}
	if !strings.Contains(string(legacyBundle), "KOSCHEI WEB3 — canonical public stylesheet") {
		t.Fatal("legacy compatibility CSS is missing the consolidation provenance header")
	}

	expectedPrimary := map[string]string{
		filepath.Clean("public/index.html"):     "/css/koschei-home.css?v=1",
		filepath.Clean("public/dashboard.html"): "/css/koschei-dashboard.css?v=1",
	}

	err = filepath.WalkDir("public", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".html") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		refs := internalPublicStylesheetRE.FindAllStringSubmatch(string(body), -1)
		if len(refs) > 1 {
			t.Errorf("%s loads %d internal CSS files; want at most one", path, len(refs))
			return nil
		}

		cleanPath := filepath.Clean(path)
		if expected, ok := expectedPrimary[cleanPath]; ok {
			if len(refs) != 1 || refs[0][1] != expected {
				got := "none"
				if len(refs) == 1 {
					got = refs[0][1]
				}
				t.Errorf("%s loads %q; want primary stylesheet %q", path, got, expected)
			}
			return nil
		}

		if len(refs) == 1 && refs[0][1] != "/css/koschei.css?v=1" {
			t.Errorf("legacy/auxiliary surface %s loads %q; want quarantined /css/koschei.css?v=1", path, refs[0][1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk public HTML: %v", err)
	}
}
