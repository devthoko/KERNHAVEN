package identity

import "testing"

// RFC 6238 appendix B (SHA-1 secret), last six digits of the 8-digit values.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		if got := totpCode(secret, unix/30); got != want {
			t.Errorf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := newRecoveryCodes()
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if hashCode("abcde-fghij") != hashCode(" ABCDEFGHIJ ") {
		t.Fatal("normalisation")
	}
}
