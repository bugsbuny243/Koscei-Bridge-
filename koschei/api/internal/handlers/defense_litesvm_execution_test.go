package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeStrictDefenseLiteSVMRequestRejectsUnknownExecutionFields(t *testing.T) {
	request := httptest.NewRequest("POST", "/api/owner/defense/litesvm-execution", strings.NewReader(`{
		"action":"enqueue",
		"profile_ref":"KHEP1-test",
		"materialization_ref":"KHM1-test",
		"commands":["sh -c whoami"]
	}`))
	recorder := httptest.NewRecorder()
	var input defenseLiteSVMExecutionRequest
	if err := decodeStrictDefenseLiteSVMRequest(recorder, request, &input); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unknown field") {
		t.Fatalf("unknown command field was accepted: input=%+v err=%v", input, err)
	}
}

func TestDecodeStrictDefenseLiteSVMRequestRejectsMultipleObjectsAndMissingRefs(t *testing.T) {
	multiple := httptest.NewRequest("POST", "/api/owner/defense/litesvm-execution", strings.NewReader(`{"action":"enqueue","profile_ref":"p","materialization_ref":"m"} {}`))
	if err := decodeStrictDefenseLiteSVMRequest(httptest.NewRecorder(), multiple, &defenseLiteSVMExecutionRequest{}); err == nil {
		t.Fatal("multiple JSON values were accepted")
	}
	missing := httptest.NewRequest("POST", "/api/owner/defense/litesvm-execution", strings.NewReader(`{"action":"enqueue","profile_ref":"","materialization_ref":"m"}`))
	if err := decodeStrictDefenseLiteSVMRequest(httptest.NewRecorder(), missing, &defenseLiteSVMExecutionRequest{}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing immutable reference was accepted: %v", err)
	}
}
