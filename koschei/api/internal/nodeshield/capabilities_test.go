package nodeshield

import "testing"

func TestValidateRuntimeCapabilitiesAllowsObserveModeWhenPreActionNotRequired(t *testing.T) {
	caps := RuntimeCapabilities{Mode: EnforcementObserveOnly, ArtifactIdentity: true}
	if err := ValidateRuntimeCapabilities(caps, false); err != nil {
		t.Fatalf("expected observe-only mode to be allowed: %v", err)
	}
}

func TestValidateRuntimeCapabilitiesRejectsMissingArtifactBinding(t *testing.T) {
	caps := RuntimeCapabilities{Mode: EnforcementPreAction, NetworkConnect: true, FileWrite: true, ProcessExec: true, PrivilegeChange: true}
	if err := ValidateRuntimeCapabilities(caps, true); err == nil {
		t.Fatal("expected missing artifact identity to fail")
	}
}

func TestValidateRuntimeCapabilitiesRejectsPartialPreActionCoverage(t *testing.T) {
	caps := RuntimeCapabilities{
		Mode:              EnforcementPreAction,
		ArtifactIdentity: true,
		NetworkConnect:    true,
		FileWrite:         true,
		ProcessExec:       true,
		PrivilegeChange:  false,
	}
	if err := ValidateRuntimeCapabilities(caps, true); err == nil {
		t.Fatal("expected partial pre-action coverage to fail")
	}
}

func TestValidateRuntimeCapabilitiesAcceptsFullPreActionCoverage(t *testing.T) {
	caps := RuntimeCapabilities{
		Mode:              EnforcementPreAction,
		ArtifactIdentity: true,
		NetworkConnect:    true,
		FileWrite:         true,
		ProcessExec:       true,
		PrivilegeChange:  true,
	}
	if err := ValidateRuntimeCapabilities(caps, true); err != nil {
		t.Fatalf("expected full pre-action coverage: %v", err)
	}
}
