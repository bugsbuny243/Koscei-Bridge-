package defensecollector

import (
	"context"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/securityevidence"
)

func TestCollectLiveV04WaitsForRealObservationWindow(t *testing.T) {
	req := collectorRequestV04(t, false, 40)
	started := time.Now()
	result, err := CollectLiveV04(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 35*time.Millisecond {
		t.Fatalf("collector sealed before live window elapsed: %s", elapsed)
	}
	if result.Binding.Status != defense.DefenseValidationObservationNoAlertV02 || result.Binding.ObservationCompletedOffsetMS < req.ObservationWindowMS {
		t.Fatalf("unexpected live no-alert binding: %#v", result.Binding)
	}
	if _, err := defense.AdaptSecurityEvidenceObservationV03(req.Control, result.Execution, result.Binding, result.Event, result.AlertEvent); err != nil {
		t.Fatal(err)
	}
}

func TestCollectLiveV04DoesNotInventAlertFromControlSignal(t *testing.T) {
	req := collectorRequestV04(t, true, 30)
	result, err := CollectLiveV04(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Execution.ControlSignaled {
		t.Fatal("fixture did not signal")
	}
	if result.Binding.Status != defense.DefenseValidationObservationNoAlertV02 || result.AlertEvent != nil {
		t.Fatalf("collector invented alert evidence: %#v", result.Binding)
	}
}

func TestCollectLiveV04AcceptsSeparateBoundAlert(t *testing.T) {
	req := collectorRequestV04(t, true, 60)
	execution := collectorExecutionV04(t, req)
	alerts := make(chan securityevidence.Event, 1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		event, err := SealAlertV04("observer:independent-test", req.Control, execution, req.Chain, time.Now())
		if err == nil {
			alerts <- event
		}
		close(alerts)
	}()
	result, err := CollectLiveV04(context.Background(), req, alerts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Binding.Status != defense.DefenseValidationObservationAlertedV02 || result.AlertEvent == nil || result.Binding.AlertObservedOffsetMS == nil {
		t.Fatalf("separate alert not bound: %#v", result.Binding)
	}
	if _, err := defense.AdaptSecurityEvidenceObservationV03(req.Control, result.Execution, result.Binding, result.Event, result.AlertEvent); err != nil {
		t.Fatal(err)
	}
}

func TestObservationV03RejectsControlConfigurationReplay(t *testing.T) {
	req := collectorRequestV04(t, false, 25)
	result, err := CollectLiveV04(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	replayed := req.Control
	replayed.ConfigurationHash = strings.Repeat("f", 64)
	if strings.EqualFold(replayed.ConfigurationHash, req.Control.ConfigurationHash) {
		replayed.ConfigurationHash = strings.Repeat("e", 64)
	}
	if _, err := defense.AdaptSecurityEvidenceObservationV03(replayed, result.Execution, result.Binding, result.Event, result.AlertEvent); err == nil {
		t.Fatal("observation replayed across control configuration")
	}
}

func TestCollectLiveV04RejectsAlertOutsideLiveWindow(t *testing.T) {
	req := collectorRequestV04(t, true, 30)
	execution := collectorExecutionV04(t, req)
	stale, err := SealAlertV04("observer:independent-test", req.Control, execution, req.Chain, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	alerts := make(chan securityevidence.Event, 1)
	alerts <- stale
	close(alerts)
	if _, err := CollectLiveV04(context.Background(), req, alerts); err == nil {
		t.Fatal("stale alert accepted into live observation window")
	}
}

func collectorRequestV04(t *testing.T, signaled bool, windowMS int64) RequestV04 {
	t.Helper()
	legacy := collectorRequestV03(t, signaled)
	var impact *int64
	if signaled {
		value := windowMS - 1
		impact = &value
	}
	return RequestV04{
		Version: VersionV04, CollectorRef: legacy.CollectorRef, Control: legacy.Control, Chain: legacy.Chain,
		CaseRef: legacy.CaseRef, CaseKind: legacy.CaseKind, TechniqueID: legacy.TechniqueID, ExecutionMode: legacy.ExecutionMode,
		ImpactOffsetMS: impact, ObservationWindowMS: windowMS, MainnetTransactionSent: false,
		ContainmentReceipt: legacy.ContainmentReceipt, ExecutionProof: legacy.ExecutionProof,
	}
}

func collectorExecutionV04(t *testing.T, req RequestV04) defense.DefenseValidationExecutionEvidenceV02 {
	t.Helper()
	execution, err := defense.AdaptExecutionIntegrityCaseV02(defense.DefenseValidationExecutionAdapterInputV02{
		CaseRef: req.CaseRef, CaseKind: req.CaseKind, TechniqueID: req.TechniqueID, ExecutionMode: req.ExecutionMode,
		ImpactOffsetMS: req.ImpactOffsetMS, ObservationWindowMS: req.ObservationWindowMS, MainnetTransactionSent: false,
		ContainmentReceipt: req.ContainmentReceipt, ExecutionProof: req.ExecutionProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return execution
}
