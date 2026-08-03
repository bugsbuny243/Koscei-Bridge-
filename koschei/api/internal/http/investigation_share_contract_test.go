package http

import (
	"os"
	"strings"
	"testing"
)

func TestInvestigationShareUsesUserReviewedXIntent(t *testing.T) {
	share := mustReadShareFixture(t, "../../public/js/investigation-share.js")
	for _, required := range []string{
		"https://x.com/intent/tweet",
		"window.open",
		"publicResultURL",
		"evidence_pending",
		"Eksik kanıt güvenli sayılmaz",
		"installRadarShare",
	} {
		if !strings.Contains(share, required) {
			t.Fatalf("investigation share module is missing %q", required)
		}
	}
	for _, forbidden := range []string{"/2/tweets", "Authorization", "Bearer ", "access_token", "api.x.com"} {
		if strings.Contains(share, forbidden) {
			t.Fatalf("investigation share module must not auto-post or hold X credentials: %q", forbidden)
		}
	}
}

func TestCustomerScanAndRadarExposeInvestigationShare(t *testing.T) {
	scanHTML := mustReadShareFixture(t, "../../public/scan.html")
	shareIndex := strings.Index(scanHTML, "/js/investigation-share.js")
	scanIndex := strings.Index(scanHTML, "/js/public-solana-scan.js")
	if shareIndex < 0 || scanIndex < 0 || shareIndex > scanIndex {
		t.Fatal("scan page must load investigation-share.js before public-solana-scan.js")
	}
	if !strings.Contains(scanHTML, "Share on X") || !strings.Contains(scanHTML, `id="shareResult"`) {
		t.Fatal("scan page is missing the English X share action")
	}

	publicScan := mustReadShareFixture(t, "../../public/js/public-solana-scan.js")
	for _, required := range []string{"KoscheiInvestigationShare", "lastSharePayload", "evidence_pending", "publicResultURL"} {
		if !strings.Contains(publicScan, required) {
			t.Fatalf("public scan share integration is missing %q", required)
		}
	}

	globalShell := mustReadShareFixture(t, "../../public/js/koschei-global-shell.js")
	for _, required := range []string{"loadInvestigationShare", "current!=='/security-radar'", "/js/investigation-share.js"} {
		if !strings.Contains(globalShell, required) {
			t.Fatalf("full Radar share loader is missing %q", required)
		}
	}
}

func mustReadShareFixture(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
