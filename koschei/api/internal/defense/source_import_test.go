package defense

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type sourceImportRoundTripper struct {
	status  int
	body    []byte
	seenURL string
}

func (c *sourceImportRoundTripper) Do(req *http.Request) (*http.Response, error) {
	c.seenURL = req.URL.String()
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(bytes.NewReader(c.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func makeSourceArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestParsePublicGitHubRepositoryURL(t *testing.T) {
	owner, repo, normalized, err := parsePublicGitHubRepositoryURL("https://github.com/ackee-blockchain/trident.git")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "ackee-blockchain" || repo != "trident" || normalized != "https://github.com/ackee-blockchain/trident" {
		t.Fatalf("unexpected repository identity: %q %q %q", owner, repo, normalized)
	}
	invalid := []string{
		"http://github.com/owner/repo",
		"https://example.com/owner/repo",
		"https://github.com/owner/repo/issues",
		"https://user:pass@github.com/owner/repo",
		"https://github.com/owner/repo?ref=main",
		"https://github.com/owner/repo#fragment",
	}
	for _, candidate := range invalid {
		if _, _, _, err := parsePublicGitHubRepositoryURL(candidate); err == nil {
			t.Fatalf("unsafe repository URL accepted: %s", candidate)
		}
	}
}

func TestFetchSourceRepositoryUsesExactCommitAndFiltersFiles(t *testing.T) {
	commit := strings.Repeat("a", 40)
	archive := makeSourceArchive(t, map[string][]byte{
		"repo-" + commit + "/Cargo.toml":                  []byte("[workspace]\nmembers=[\"programs/demo\"]\n"),
		"repo-" + commit + "/Anchor.toml":                 []byte("[provider]\ncluster=\"mainnet\"\n"),
		"repo-" + commit + "/programs/demo/src/lib.rs":    []byte("use anchor_lang::prelude::*;\n#[program]\npub mod demo {}\n"),
		"repo-" + commit + "/tests/demo.ts":               []byte("describe('demo',()=>{});\n"),
		"repo-" + commit + "/target/deploy/demo.so":       []byte{0, 1, 2, 3},
		"repo-" + commit + "/node_modules/pkg/index.js":   []byte("ignored"),
		"repo-" + commit + "/assets/logo.png":             []byte{0, 1, 2},
		"repo-" + commit + "/programs/demo/src/binary.rs": []byte{'a', 0, 'b'},
		"repo-" + commit + "/../escape.rs":                []byte("pub fn escape() {}"),
	})
	client := &sourceImportRoundTripper{status: http.StatusOK, body: archive}
	result, err := FetchSourceRepository(context.Background(), client, SourceImportInput{
		ProgramID:     "Program111111111111111111111111111111111",
		Network:       "mainnet",
		RepositoryURL: "https://github.com/owner/repo",
		CommitSHA:     commit,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedURL := "https://codeload.github.com/owner/repo/zip/" + commit
	if client.seenURL != expectedURL {
		t.Fatalf("unexpected archive URL: %s", client.seenURL)
	}
	for _, required := range []string{"Cargo.toml", "Anchor.toml", "programs/demo/src/lib.rs", "tests/demo.ts"} {
		if _, ok := result.Bundle[required]; !ok {
			t.Fatalf("required source missing: %s bundle=%v", required, result.Bundle)
		}
	}
	for _, forbidden := range []string{"target/deploy/demo.so", "node_modules/pkg/index.js", "assets/logo.png", "programs/demo/src/binary.rs", "escape.rs"} {
		if _, ok := result.Bundle[forbidden]; ok {
			t.Fatalf("forbidden file imported: %s", forbidden)
		}
	}
	if result.ArchiveHash == "" || result.FileCount != 4 || result.SkippedFiles < 4 {
		t.Fatalf("unexpected import metrics: %+v", result)
	}
	if len(result.BundleJSON) == 0 || result.RepositoryURL != "https://github.com/owner/repo" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestFetchSourceRepositoryRejectsNonExactCommit(t *testing.T) {
	client := &sourceImportRoundTripper{status: http.StatusOK, body: []byte("unused")}
	_, err := FetchSourceRepository(context.Background(), client, SourceImportInput{
		ProgramID:     "Program111111111111111111111111111111111",
		RepositoryURL: "https://github.com/owner/repo",
		CommitSHA:     "main",
	})
	if err == nil {
		t.Fatal("branch name was accepted instead of exact commit")
	}
	if client.seenURL != "" {
		t.Fatal("network request occurred before commit validation")
	}
}

func TestFetchSourceRepositoryRejectsHTTPFailure(t *testing.T) {
	client := &sourceImportRoundTripper{status: http.StatusNotFound, body: []byte("missing")}
	_, err := FetchSourceRepository(context.Background(), client, SourceImportInput{
		ProgramID:     "Program111111111111111111111111111111111",
		RepositoryURL: "https://github.com/owner/repo",
		CommitSHA:     strings.Repeat("b", 40),
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractSourceBundleRejectsEmptyRelevantCorpus(t *testing.T) {
	archive := makeSourceArchive(t, map[string][]byte{
		"repo/assets/logo.png": []byte{1, 2, 3},
		"repo/target/demo.so":  []byte{4, 5, 6},
	})
	if _, _, _, _, _, err := extractSourceBundleFromZip(archive); err == nil {
		t.Fatal("archive without supported source was accepted")
	}
}
