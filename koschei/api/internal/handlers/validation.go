package handlers

import (
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validEmail(email string) bool { return emailRe.MatchString(email) }

func validPlan(plan string) bool {
	switch plan {
	case "free", "professional":
		return true
	default:
		return false
	}
}

func validStatus(status string) bool {
	switch status {
	case "queued", "running", "completed", "failed", "cancelled", "review_needed":
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type rateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func NewLimiter() *rateLimiter { return &rateLimiter{hits: map[string][]time.Time{}} }
func (rl *rateLimiter) allow(key string, max int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	arr := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			arr = append(arr, t)
		}
	}
	if len(arr) >= max {
		rl.hits[key] = arr
		return false
	}
	rl.hits[key] = append(arr, now)
	return true
}

func validPaidActivationPlan(plan string) bool {
	return plan == "professional"
}
