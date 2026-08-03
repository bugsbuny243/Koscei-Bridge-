package main

import (
	"os"
	"strings"
	"testing"
)

func TestAuthPresentationInstallsSameOriginEmailContract(t *testing.T) {
	body, err := os.ReadFile("public/js/english-auth-presentation.js")
	if err != nil {
		t.Fatalf("read auth presentation runtime: %v", err)
	}
	script := string(body)
	for _, required := range []string{
		"/api/auth/login",
		"/api/auth/register",
		"credentials:'same-origin'",
		"window.__koscheiSameOriginEmailAuthInstalled",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("same-origin auth runtime is missing %q", required)
		}
	}
	if strings.Contains(script, "fetch(baseURL+'/sign-in/email'") || strings.Contains(script, "fetch(baseURL+'/sign-up/email'") {
		t.Fatal("presentation runtime must not call Neon email endpoints directly")
	}
}

func TestAuthPresentationCacheVersionIsBumped(t *testing.T) {
	if !strings.Contains(authEnglishOverlayScript, "english-auth-presentation.js?v=2") {
		t.Fatalf("auth presentation script was not cache-busted: %s", authEnglishOverlayScript)
	}
}
