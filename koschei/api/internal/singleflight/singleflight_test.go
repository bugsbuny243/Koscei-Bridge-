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

func TestDoContextLeaderCancellationDoesNotCancelSharedWork(t *testing.T) {
	var group Group
	started := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan error, 1)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	go func() {
		_, err, shared := group.DoContext(leaderCtx, "tx", func() (interface{}, error) {
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
	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error=%v want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled leader did not stop waiting")
	}

	type followerResult struct {
		value  interface{}
		err    error
		shared bool
	}
	followerDone := make(chan followerResult, 1)
	go func() {
		value, err, shared := group.DoContext(context.Background(), "tx", func() (interface{}, error) {
			return nil, errors.New("duplicate unexpectedly started new work")
		})
		followerDone <- followerResult{value: value, err: err, shared: shared}
	}()

	select {
	case result := <-followerDone:
		t.Fatalf("follower returned before shared work release: value=%#v err=%v shared=%v", result.value, result.err, result.shared)
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case result := <-followerDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.shared {
			t.Fatal("follower was not marked shared")
		}
		if result.value != "ok" {
			t.Fatalf("follower value=%#v want ok", result.value)
		}
	case <-time.After(time.Second):
		t.Fatal("follower did not receive shared result")
	}
}
