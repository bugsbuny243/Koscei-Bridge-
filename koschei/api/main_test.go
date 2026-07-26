package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveStaticDirPrefersLocalPublicDirectory(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		t.Fatalf("create local public dir: %v", err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(root); err != nil {
		t.Fatalf("change working directory: %v", err)
	}

	if got := resolveStaticDir(""); got != "public" {
		t.Fatalf("resolveStaticDir() = %q, want public", got)
	}
}

func TestResolveStaticDirHonorsConfiguredPath(t *testing.T) {
	if got := resolveStaticDir("/custom/public"); got != "/custom/public" {
		t.Fatalf("resolveStaticDir(configured) = %q, want /custom/public", got)
	}
}

func TestNewHTTPServerSetsProductionTimeouts(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newHTTPServer("9090", handler)
	if server.Addr != ":9090" || server.Handler == nil {
		t.Fatalf("server=%#v", server)
	}
	if server.ReadHeaderTimeout != httpReadHeaderTimeout || server.ReadTimeout != httpReadTimeout || server.WriteTimeout != httpWriteTimeout || server.IdleTimeout != httpIdleTimeout {
		t.Fatalf("timeouts were not applied: %#v", server)
	}
	if server.WriteTimeout < 8*time.Minute {
		t.Fatalf("write timeout=%s is too short for bounded actor/forensics routes", server.WriteTimeout)
	}
}
