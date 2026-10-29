package live

import "testing"

func TestHealthOf(t *testing.T) {
	for in, want := range map[string]string{
		"Up 3 minutes (healthy)":         "healthy",
		"Up 1 second (health: starting)": "health: starting",
		"Up 2 hours":                     "",
		"Exited (0) 5 seconds ago":       "0",
		"Up About a minute (unhealthy)":  "unhealthy",
	} {
		if got := healthOf(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
