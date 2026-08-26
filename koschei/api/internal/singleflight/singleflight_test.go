package singleflight

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDoContextLetsDuplicateStopWaitingWithoutCancellingLeader(t *testing.T) {
	var group Group
	started := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan error, 1)

	go func() {
		_, err, shared := group.DoContext(context.Background(), "tx", func() (interface{}, error) {
			close(started)
			<-release
			return "ok", nil
		})
		if shared {
			leaderDone <- errors.New("leader was unexpectedly marked shared")
			return
		}
		leaderDone <- err
	}()

	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	startedWait := time.Now()
	value, err, shared := group.DoContext(ctx, "tx", func() (interface{}, error) {
		return "duplicate-should-not-run", nil
	})
	if !shared {
		t.Fatal("duplicate was not marked shared")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("duplicate error=%v want context deadline exceeded", err)
	}
	if value != nil {
		t.Fatalf("cancelled duplicate value=%#v want nil", value)
	}
	if elapsed := time.Since(startedWait); elapsed > 250*time.Millisecond {
		t.Fatalf("duplicate cancellation was not prompt: %s", elapsed)
	}

	close(release)
	select {
	case err := <-leaderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("leader did not finish after duplicate cancelled")
	}
}
