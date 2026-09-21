// Package id produces short, sortable, collision-resistant identifiers.
//
// We deliberately avoid pulling a UUID dependency: a time-ordered prefix keeps
// audit records and approval queue entries naturally sorted when dumped.
package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

var counter atomic.Uint64

// New returns an identifier such as "req_1a2b3c4d5e6f7a8b".
func New(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal for security-relevant ids; fall back to
		// the monotonic counter rather than returning a guessable constant.
		n := counter.Add(1)
		return fmt.Sprintf("%s_%012x", prefix, uint64(time.Now().UnixNano())^n)
	}
	n := counter.Add(1)
	// 48 bits of entropy + 16 bits of local counter is plenty for request ids.
	suffix := hex.EncodeToString(b[:6])
	return fmt.Sprintf("%s_%s%04x", prefix, suffix, uint16(n))
}

// NewToken returns a high-entropy secret suitable for signing keys.
func NewToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
