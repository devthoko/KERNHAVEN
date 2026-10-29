package alerts

import (
	"io"

	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
)

// Guard checks channel destinations (ADR-0028).
type Guard = netguard.Guard

// ErrForbiddenAddress is a destination the Core may not reach.
var ErrForbiddenAddress = netguard.ErrForbiddenAddress

// drain reads at most 64 KiB of a response for error messages.
func drain(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 64<<10))
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
