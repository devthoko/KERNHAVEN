package identity

import (
	"sync"
	"time"
)

// limiter is a per-key token bucket for authentication attempts.
type limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	perToken time.Duration
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const maxBuckets = 10000

func newLimiter(capacity int, perToken time.Duration, now func() time.Time) *limiter {
	return &limiter{buckets: map[string]*bucket{}, capacity: float64(capacity), perToken: perToken, now: now}
}

// allow consumes one token for key, or reports how long to wait.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.evictFull(now)
		}
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens += float64(now.Sub(b.last)) / float64(l.perToken)
	if b.tokens > l.capacity {
		b.tokens = l.capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) * float64(l.perToken))
	return false, wait
}

// evictFull drops buckets that have refilled completely; they carry no state.
func (l *limiter) evictFull(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+float64(now.Sub(b.last))/float64(l.perToken) >= l.capacity {
			delete(l.buckets, k)
		}
	}
}
