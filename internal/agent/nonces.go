package agent

import (
	"sync"
	"time"
)

// nonceCache remembers grant nonces until their grant expires (AT-M4-04).
// When full it refuses new nonces (fail closed) instead of forgetting old ones.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	max  int
}

func newNonceCache(max int) *nonceCache {
	return &nonceCache{seen: map[string]time.Time{}, max: max}
}

// use records nonce until expiry and reports whether it was unused.
func (c *nonceCache) use(nonce string, expiry, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) >= c.max {
		for n, exp := range c.seen {
			if now.After(exp) {
				delete(c.seen, n)
			}
		}
		if len(c.seen) >= c.max {
			return false
		}
	}
	if _, dup := c.seen[nonce]; dup {
		return false
	}
	c.seen[nonce] = expiry
	return true
}
