package defense

import "testing"

func TestNormalizeDeploymentSnapshotLookupDeterministic(t *testing.T) {
	ids, err := normalizeDeploymentSnapshotLookup([]string{" ProgramB ", "ProgramA", "ProgramB", "", "ProgramC"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ProgramA", "ProgramB", "ProgramC"}
	if len(ids) != len(want) {
		t.Fatalf("ids=%v want=%v", ids, want)
	}
	for index := range want {
		if ids[index] != want[index] {
			t.Fatalf("ids=%v want=%v", ids, want)
		}
	}
}

func TestNormalizeDeploymentSnapshotLookupRejectsUnboundedRequest(t *testing.T) {
	ids := make([]string, maxProgramDeploymentSnapshotLookup+1)
	for index := range ids {
		ids[index] = "Program" + string(rune('A'+index))
	}
	if _, err := normalizeDeploymentSnapshotLookup(ids); err == nil {
		t.Fatal("unbounded deployment snapshot lookup was accepted")
	}
}
