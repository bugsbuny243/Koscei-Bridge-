package workerwake

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSignalWakesWaiter(t *testing.T) {
	gate := NewGate()
	go func() {
		time.Sleep(10 * time.Millisecond)
		gate.Signal()
	}()
	start := time.Now()
	if signalled := gate.Wait(context.Background(), time.Minute); !signalled {
		t.Fatal("Wait reported a timeout wake, want signal wake")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Wait blocked for %s despite a signal", elapsed)
	}
}

func TestSignalBeforeWaitIsNotLost(t *testing.T) {
	// A producer may enqueue while the worker is mid-batch. That wake must
	// survive until the next Wait, otherwise the row waits for the ceiling.
	gate := NewGate()
	gate.Signal()
	if signalled := gate.Wait(context.Background(), time.Minute); !signalled {
		t.Fatal("a signal sent before Wait was dropped")
	}
}

func TestSignalDoesNotBlockWhenNobodyWaits(t *testing.T) {
	// Signal runs inside request handlers, so it must never block even if the
	// worker is busy and many enqueues arrive at once.
	gate := NewGate()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			gate.Signal()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Signal blocked")
	}
}

func TestSignalsCoalesce(t *testing.T) {
	// Many enqueues collapse into one wake: the worker drains in batches, so a
	// per-row wake queue would only cause redundant empty passes.
	gate := NewGate()
	gate.Signal()
	gate.Signal()
	gate.Signal()
	if signalled := gate.Wait(context.Background(), time.Minute); !signalled {
		t.Fatal("first Wait did not observe the signal")
	}
	if signalled := gate.Wait(context.Background(), 20*time.Millisecond); signalled {
		t.Fatal("coalesced signals produced more than one wake")
	}
}

func TestDrainClearsPendingSignal(t *testing.T) {
	gate := NewGate()
	gate.Signal()
	gate.Drain()
	if signalled := gate.Wait(context.Background(), 20*time.Millisecond); signalled {
		t.Fatal("Drain left a pending signal behind")
	}
}

func TestDrainOnEmptyGateDoesNotBlock(t *testing.T) {
	gate := NewGate()
	done := make(chan struct{})
	go func() { gate.Drain(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain blocked on an empty gate")
	}
}

func TestWaitReturnsOnContextCancel(t *testing.T) {
	gate := NewGate()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if signalled := gate.Wait(ctx, time.Hour); signalled {
		t.Fatal("cancelled context reported a signal wake")
	}
}

func TestWaitTimesOut(t *testing.T) {
	gate := NewGate()
	if signalled := gate.Wait(context.Background(), 10*time.Millisecond); signalled {
		t.Fatal("timeout wake reported as a signal wake")
	}
}

func TestNilGateIsSafe(t *testing.T) {
	// Workers hold gates from Get, but a nil gate must not panic a background
	// goroutine if a future caller constructs one by value.
	var gate *Gate
	gate.Signal()
	gate.Drain()
	if signalled := gate.Wait(context.Background(), time.Millisecond); signalled {
		t.Fatal("nil gate reported a signal")
	}
}

func TestGetReturnsSameGatePerName(t *testing.T) {
	// Producers and consumers live in different packages and only agree on the
	// name; if Get returned distinct gates, every wake would be lost.
	first := Get("test-shared-gate")
	second := Get("test-shared-gate")
	if first != second {
		t.Fatal("Get returned different gates for one name")
	}
	if same := Get("test-other-gate"); same == first {
		t.Fatal("Get returned one gate for two different names")
	}
}

func TestRegistrySignalReachesConsumerGate(t *testing.T) {
	gate := Get("test-registry-signal")
	Signal("test-registry-signal")
	if signalled := gate.Wait(context.Background(), time.Minute); !signalled {
		t.Fatal("registry Signal did not reach the named gate")
	}
}

func TestRecoveryCeilingDefault(t *testing.T) {
	t.Setenv("KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS", "")
	if got := RecoveryCeiling(); got != defaultRecoveryCeiling {
		t.Fatalf("RecoveryCeiling() = %s, want %s", got, defaultRecoveryCeiling)
	}
}

func TestRecoveryCeilingClampsUnsafeValues(t *testing.T) {
	// The floor matters most: a small value would recreate the high-frequency
	// empty-query pattern that gate #697 exists to remove.
	cases := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"below floor", "1", minRecoveryCeiling},
		{"zero", "0", minRecoveryCeiling},
		{"negative", "-30", minRecoveryCeiling},
		{"above ceiling", "999999", maxRecoveryCeiling},
		{"unparseable", "soon", defaultRecoveryCeiling},
		{"accepted", "600", 10 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS", tc.env)
			if got := RecoveryCeiling(); got != tc.want {
				t.Fatalf("RecoveryCeiling() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestWaitClampsSleepToCeiling(t *testing.T) {
	// A far-future scheduled retry must not park the worker past the recovery
	// ceiling, or a wake-up that cannot arrive in-process would never recover.
	t.Setenv("KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS", "60")
	gate := NewGate()
	start := time.Now()
	go func() {
		time.Sleep(10 * time.Millisecond)
		gate.Signal()
	}()
	gate.Wait(context.Background(), 30*24*time.Hour)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Wait honored a 30-day sleep instead of clamping: %s", elapsed)
	}
}

func TestNextDueSleepWithoutDatabaseReturnsCeiling(t *testing.T) {
	// A nil or unavailable database must fall back to the ceiling rather than to
	// zero, which would spin against a database that may be waking or degraded.
	t.Setenv("KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS", "300")
	if got := NextDueSleep(context.Background(), nil, WebhookDelivery); got != 5*time.Minute {
		t.Fatalf("NextDueSleep(nil db) = %s, want 5m", got)
	}
}

func TestWaitTreatsNonPositiveSleepAsCeiling(t *testing.T) {
	t.Setenv("KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS", "60")
	gate := NewGate()
	gate.Signal()
	start := time.Now()
	if signalled := gate.Wait(context.Background(), 0); !signalled {
		t.Fatal("pending signal not observed")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("zero sleep did not return promptly on signal: %s", elapsed)
	}
}

func TestDueQueryExcludesPausedWebhookEndpoints(t *testing.T) {
	query, ok := dueQuery(WebhookDelivery)
	if !ok {
		t.Fatal("webhook delivery queue has no due query")
	}
	for _, fragment := range []string{"JOIN webhook_endpoints", "e.status='active'"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("webhook due query missing %q: %s", fragment, query)
		}
	}
}

func TestDueQueryRejectsUnknownQueue(t *testing.T) {
	if query, ok := dueQuery("unknown"); ok || query != "" {
		t.Fatalf("unknown queue returned query=%q ok=%v", query, ok)
	}
}
