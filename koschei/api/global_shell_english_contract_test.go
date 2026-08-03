package main

import (
	"os"
	"strings"
	"testing"
)

func TestGlobalShellProducesEnglishNavigationAndMessages(t *testing.T) {
	body, err := os.ReadFile("public/js/koschei-global-shell.js")
	if err != nil {
		t.Fatalf("read global shell: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"['/live','Live SOC']",
		"['/cases','Cases']",
		"['/scan','Token Scan']",
		"['/transaction-shield','Transaction Shield']",
		"['/safe-check','Safe Check']",
		"['/security-radar','Security Radar']",
		"['/dashboard','Workspace']",
		"nav.setAttribute('aria-label','Main navigation')",
		"document.documentElement.lang='en'",
		"The evidence service did not respond within",
		"DEGRADED DEPENDENCY — Live security evidence is unavailable.",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("global shell missing English contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"document.documentElement.lang='tr'",
		"['/scan','Token Tara']",
		"nav.setAttribute('aria-label','Ana menü')",
		"run.textContent='Kontrol ediliyor…'",
		"Koschei ARVIS · Solana güvenlik merkezi</span>",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("global shell still produces Turkish UI contract %q", forbidden)
		}
	}
}
