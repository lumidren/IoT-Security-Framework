package storetest

import (
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// TestSuiteAgainstMemory runs the conformance suite in-package so the suite's
// own statements are covered.
func TestSuiteAgainstMemory(t *testing.T) {
	Run(t, func(t *testing.T) store.Store {
		m := store.NewMemory()
		t.Cleanup(func() { _ = m.Close() })
		return m
	})
}
