package handlers

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestConservativeStreamflowUnlockRequiresMultipleScheduleTimes(t *testing.T) {
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	data := make([]byte, 64)
	binary.LittleEndian.PutUint64(data[8:16], uint64(now.Add(24*time.Hour).Unix()))
	if _, ok := conservativeStreamflowUnlock(data, now); ok {
		t.Fatal("single coincidental timestamp was accepted")
	}
	binary.LittleEndian.PutUint64(data[16:24], uint64(now.Add(48*time.Hour).Unix()))
	unlock, ok := conservativeStreamflowUnlock(data, now)
	if !ok || !unlock.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("unlock=%v ok=%v", unlock, ok)
	}
}
