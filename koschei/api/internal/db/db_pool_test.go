package db

import "testing"

func TestEnvNonNegativeIntAcceptsZero(t *testing.T) {
	t.Setenv("DB_MAX_IDLE_CONNS", "0")
	if got := envNonNegativeInt("DB_MAX_IDLE_CONNS", 5); got != 0 {
		t.Fatalf("envNonNegativeInt() = %d, want 0", got)
	}
}

func TestEnvNonNegativeIntRejectsNegativeAndInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "not-a-number"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DB_CONN_MAX_IDLE_TIME_SECONDS", value)
			if got := envNonNegativeInt("DB_CONN_MAX_IDLE_TIME_SECONDS", 60); got != 60 {
				t.Fatalf("envNonNegativeInt() = %d, want fallback 60", got)
			}
		})
	}
}
