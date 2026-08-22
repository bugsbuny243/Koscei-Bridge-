package main

import (
	"os"
	"strings"
	"testing"
)

func TestWeb3ProductBoundaryKeepsARVISInsideKoscheiWeb3(t *testing.T) {
	architecture, err := os.ReadFile("public/architecture.html")
	if err != nil {
		t.Fatalf("read architecture: %v", err)
	}
	text := string(architecture)
	for _, required := range []string{
		"ARVIS is the intelligence and evidence engine inside Koschei Web3.",
		"ARVIS intelligence and evidence",
		"Koschei Web3 · ARVIS Intelligence · Architecture",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("architecture missing ARVIS/Web3 boundary %q", required)
		}
	}

	shell, err := os.ReadFile("public/js/koschei-global-shell.js")
	if err != nil {
		t.Fatalf("read global shell: %v", err)
	}
	if !strings.Contains(string(shell), "Koschei Web3 · ARVIS Intelligence") {
		t.Fatal("global shell must present ARVIS inside the Koschei Web3 brand")
	}
	if strings.Contains(string(shell), "<span>Koschei ARVIS · Solana security center</span>") {
		t.Fatal("global shell must not present Koschei ARVIS as a separate product brand")
	}
}

func TestWeb3RepositoryDoesNotOwnMatrixNamespace(t *testing.T) {
	if _, err := os.Stat("internal/matrixcontainment"); !os.IsNotExist(err) {
		t.Fatalf("Matrix namespace must not exist in Web3: err=%v", err)
	}
	if _, err := os.Stat("internal/executioncontainment"); err != nil {
		t.Fatalf("Web3 execution containment namespace missing: %v", err)
	}

	agents, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	text := string(agents)
	if !strings.Contains(text, "Matrix belongs to Koschei Lang, not Koschei Web3.") {
		t.Fatal("repository contract must reserve Matrix for Koschei Lang")
	}
	if !strings.Contains(text, "ARVIS is a core intelligence and evidence engine inside Koschei Web3.") {
		t.Fatal("repository contract must keep ARVIS inside Koschei Web3")
	}
}
