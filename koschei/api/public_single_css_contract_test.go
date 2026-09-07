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

func TestPublicSiteUsesOneCanonicalCSSFile(t *testing.T) {
	files, err := filepath.Glob("public/css/*.css")
	if err != nil {
		t.Fatalf("glob public css: %v", err)
	}
	sort.Strings(files)
	want := []string{filepath.FromSlash("public/css/koschei.css")}
	if len(files) != 1 || files[0] != want[0] {
		t.Fatalf("public CSS contract drifted: got %v, want %v", files, want)
	}

	bundle, err := os.ReadFile(want[0])
	if err != nil {
		t.Fatalf("read canonical CSS: %v", err)
	}
	if !strings.Contains(string(bundle), "KOSCHEI WEB3 — canonical public stylesheet") {
		t.Fatal("canonical CSS is missing the consolidation provenance header")
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
		if len(refs) == 1 && refs[0][1] != "/css/koschei.css?v=1" {
			t.Errorf("%s loads %q; want canonical /css/koschei.css?v=1", path, refs[0][1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk public HTML: %v", err)
	}
}
