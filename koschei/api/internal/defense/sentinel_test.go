package defense

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCompareDeploymentSnapshotsDetectsCriticalBinaryAndAuthorityChanges(t *testing.T) {
	previous := DeploymentSnapshot{
		SnapshotRef:          "KDS1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LoaderID:             UpgradeableLoaderID,
		LoaderKind:           "bpf_upgradeable_loader",
		ProgramDataAddress:   "ProgramDataA",
		CanonicalBinaryHash:  "sha256:" + repeatHex("a", 64),
		UpgradeAuthority:     "AuthorityA",
		UpgradeAuthorityOpen: true,
		MatchStatus:          "matched_full_binary",
	}
	current := previous
	current.SnapshotRef = "KDS1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	current.CanonicalBinaryHash = "sha256:" + repeatHex("b", 64)
	current.UpgradeAuthority = "AuthorityB"
	current.MatchStatus = "mismatched"
	change := CompareDeploymentSnapshots(previous, current)
	if !change.Changed || change.Severity != "critical" {
		t.Fatalf("unexpected change: %+v", change)
	}
	for _, expected := range []string{"bytecode_changed", "upgrade_authority_changed", "source_match_lost"} {
		if !containsString(change.ChangeTypes, expected) {
			t.Fatalf("missing change type %s: %+v", expected, change)
		}
	}
	if change.Summary == "" {
		t.Fatal("change summary is empty")
	}
}

func TestCompareDeploymentSnapshotsTreatsAuthorityRevocationAsInformational(t *testing.T) {
	previous := DeploymentSnapshot{LoaderID: UpgradeableLoaderID, LoaderKind: "bpf_upgradeable_loader", ProgramDataAddress: "PD",
		CanonicalBinaryHash: "sha256:" + repeatHex("c", 64), UpgradeAuthority: "AuthorityA", UpgradeAuthorityOpen: true,
		MatchStatus: "matched_full_binary"}
	current := previous
	current.UpgradeAuthority = ""
	current.UpgradeAuthorityOpen = false
	change := CompareDeploymentSnapshots(previous, current)
	if !change.Changed || change.Severity != "informational" || !containsString(change.ChangeTypes, "upgrade_authority_revoked") {
		t.Fatalf("unexpected revocation change: %+v", change)
	}
}

func TestCompareDeploymentSnapshotsIgnoresObservationSlotOnly(t *testing.T) {
	previous := DeploymentSnapshot{LoaderID: UpgradeableLoaderID, LoaderKind: "bpf_upgradeable_loader", ProgramDataAddress: "PD",
		CanonicalBinaryHash: "sha256:" + repeatHex("d", 64), UpgradeAuthority: "Authority", UpgradeAuthorityOpen: true,
		MatchStatus: "matched_full_binary", AccountSlot: 100, DeploymentSlot: 90}
	current := previous
	current.AccountSlot = 200
	change := CompareDeploymentSnapshots(previous, current)
	if change.Changed || len(change.ChangeTypes) != 0 {
		t.Fatalf("observation slot created a false change: %+v", change)
	}
}

func TestProgramMonitorUpsertAndDisable(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	programID := fmt.Sprintf("CISentinelProgram%d", time.Now().UnixNano())
	monitor, err := UpsertProgramMonitor(ctx, db, ProgramMonitorInput{ProgramID: programID, Network: "mainnet", IntervalSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	if !monitor.Active || monitor.IntervalSeconds != 120 || monitor.LastStatus != "pending" || monitor.Network != "mainnet" {
		t.Fatalf("unexpected monitor: %+v", monitor)
	}
	disabled, err := DisableProgramMonitor(ctx, db, monitor.MonitorRef)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Active || disabled.LastStatus != "disabled" {
		t.Fatalf("monitor was not disabled: %+v", disabled)
	}
}

func repeatHex(value string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += value
	}
	return out
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
