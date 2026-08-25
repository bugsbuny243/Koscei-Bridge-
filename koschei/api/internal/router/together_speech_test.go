package router

import "testing"

func TestDefaultTogetherVoice(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"cartesia/sonic", "friendly sidekick"},
		{"cartesia/sonic-2", "laidback woman"},
		{"hexgrad/Kokoro-82M", "af_alloy"},
		{"canopylabs/orpheus-3b-0.1-ft", "tara"},
		{"custom/provider", "friendly sidekick"},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			if got := defaultTogetherVoice(tc.model); got != tc.want {
				t.Fatalf("defaultTogetherVoice(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}
