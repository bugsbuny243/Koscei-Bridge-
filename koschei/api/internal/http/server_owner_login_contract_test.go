package http

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOwnerLoginRouteCannotRegressToMasterSecretCookieHandler(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test source path")
	}
	serverSource, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "server.go"))
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	source := string(serverSource)
	secureRoute := `mux.HandleFunc("/api/owner/login", method("POST", h.OwnerLoginAudited))`
	if !strings.Contains(source, secureRoute) {
		t.Fatalf("owner login route must remain attached to OwnerLoginAudited")
	}
	legacyRoute := `mux.HandleFunc("/api/owner/login", method("POST", h.OwnerLogin))`
	if strings.Contains(source, legacyRoute) {
		t.Fatalf("owner login route must never be attached to legacy OwnerLogin")
	}
}
