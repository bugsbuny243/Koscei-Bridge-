package singleflight

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoContextSharesOneInFlightExecution(t *testing.T) {
	var group Group
	var executions atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan struct{})

	go func() {
		defer close(leaderDone)
		value, err, shared := group.DoContext(context.Background(), "same-key", func() (interface{}, error) {
			executions.Add(1)
			close(started)
			<-release
			return "canonical", nil
		})
		if err != nil || shared || value != "canonical" {
			t.Errorf("leader result value=%v err=%v shared=%v", value, err, shared)
		}
	}()

	<-started
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		value, err, shared := group.DoContext(context.Background(), "same-key", func() (interface{}, error) {
			executions.Add(1)
			return "unexpected", nil
		})
		if err != nil || !shared || value != "canonical" {
			t.Errorf("waiter result value=%v err=%v shared=%v", value, err, shared)
		}
	}()

	time.Sleep(10 * time.Millisecond)
	close(release)
	<-leaderDone
	<-waiterDone
	if got := executions.Load(); got != 1 {
		t.Fatalf("executions=%d want 1", got)
	}
}

func TestDoContextDuplicateCanCancelWithoutCancelingLeader(t *testing.T) {
	var group Group
	started := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan error, 1)

	go func() {
		_, err, _ := group.DoContext(context.Background(), "same-key", func() (interface{}, error) {
			close(started)
			<-release
			return "canonical", nil
		})
		leaderDone <- err
	}()

	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	value, err, shared := group.DoContext(ctx, "same-key", func() (interface{}, error) {
		t.Fatal("duplicate function must not execute")
		return nil, nil
	})
	if value != nil {
		t.Fatalf("canceled duplicate value=%v want nil", value)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled duplicate err=%v want deadline exceeded", err)
	}
	if !shared {
		t.Fatal("canceled duplicate was not reported as shared")
	}

	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader was canceled by duplicate waiter: %v", err)
	}
}
