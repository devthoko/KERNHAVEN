package identity

import (
	"strings"
	"testing"
	"time"
)

var testParams = HashParams{Memory: 64, Time: 1, Threads: 1}

// AT-F08-02
func TestHashAndVerify(t *testing.T) {
	h, err := hashPassword(testParams, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", h)
	}
	if ok, err := verifyPassword(h, "correct horse battery"); err != nil || !ok {
		t.Fatalf("verify correct: ok=%v err=%v", ok, err)
	}
	if ok, err := verifyPassword(h, "correct horse batterY"); err != nil || ok {
		t.Fatalf("verify wrong: ok=%v err=%v", ok, err)
	}
	h2, _ := hashPassword(testParams, "correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyRejectsMalformedOrDangerousHashes(t *testing.T) {
	valid, _ := hashPassword(testParams, "x")
	parts := strings.Split(valid, "$")
	cases := map[string]string{
		"empty":        "",
		"bcrypt":       "$2a$10$abcdefghijklmnopqrstuv",
		"argon2i":      strings.Replace(valid, "argon2id", "argon2i", 1),
		"bad version":  strings.Replace(valid, "v=19", "v=16", 1),
		"huge memory":  "$argon2id$v=19$m=4194304,t=1,p=1$" + parts[4] + "$" + parts[5],
		"zero time":    "$argon2id$v=19$m=64,t=0,p=1$" + parts[4] + "$" + parts[5],
		"short salt":   "$argon2id$v=19$m=64,t=1,p=1$YWJj$" + parts[5],
		"bad base64":   "$argon2id$v=19$m=64,t=1,p=1$!!!$" + parts[5],
		"missing part": "$argon2id$v=19$m=64,t=1,p=1$" + parts[4],
	}
	for name, h := range cases {
		if ok, err := verifyPassword(h, "x"); err == nil || ok {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
}

// AT-F08-02
func TestPasswordPolicy(t *testing.T) {
	good := []string{"correct horse battery", "Tr0ub4dor&3xyz", "ünïcödé-pässwörd"}
	for _, p := range good {
		if err := CheckPasswordPolicy("alice", p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	bad := map[string]string{
		"short":            "short pw",
		"too long":         strings.Repeat("ab12-", 60),
		"contains user":    "my-ALICE-password-1",
		"few distinct":     "abababababababab",
		"common":           "Password1234",
		"invalid utf8":     "abcdefghijk\xff",
		"eleven runes":     "abcdefghijk",
		"common lowercase": "QWERTYUIOPAS",
	}
	for name, p := range bad {
		if err := CheckPasswordPolicy("alice", p); err == nil {
			t.Errorf("%s: %q accepted", name, p)
		}
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter(3, 10*time.Second, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("attempt %d denied", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait != 10*time.Second {
		t.Fatalf("4th attempt: ok=%v wait=%s", ok, wait)
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("other key affected")
	}
	now = now.Add(10 * time.Second)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("not refilled")
	}
}

func TestLimiterBoundsMemory(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter(2, time.Second, func() time.Time { return now })
	for i := 0; i < maxBuckets+50; i++ {
		l.allow(string(rune(i)))
		now = now.Add(time.Millisecond)
	}
	now = now.Add(time.Hour)
	l.allow("trigger")
	if len(l.buckets) > maxBuckets {
		t.Fatalf("buckets = %d", len(l.buckets))
	}
}
