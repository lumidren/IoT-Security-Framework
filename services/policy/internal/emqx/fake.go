package emqx

import (
	"context"
	"sync"
)

// Fake is an in-memory Kicker for tests. Every call is recorded and, when Kicked has room, the
// client id is also sent on it so tests can wait for the call with a timeout.
type Fake struct {
	mu    sync.Mutex
	calls []string
	err   error

	// Kicked receives the client id of every Kick call (buffered; never blocks the caller).
	Kicked chan string
}

// NewFake returns a Fake whose Kicked channel buffers 64 ids.
func NewFake() *Fake { return &Fake{Kicked: make(chan string, 64)} }

// Kick implements Kicker.
func (f *Fake) Kick(_ context.Context, clientID string) error {
	f.mu.Lock()
	f.calls = append(f.calls, clientID)
	err := f.err
	f.mu.Unlock()
	select {
	case f.Kicked <- clientID:
	default:
	}
	return err
}

// Calls returns a copy of the recorded client ids.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// SetErr makes subsequent Kick calls return err.
func (f *Fake) SetErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}
