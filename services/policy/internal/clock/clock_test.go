package clock

import (
	"testing"
	"time"
)

func TestRealNow(t *testing.T) {
	before := time.Now()
	got := Real{}.Now()
	if got.Before(before) {
		t.Fatalf("Real.Now went backwards: %v < %v", got, before)
	}
}

func TestFake(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f := NewFake(start)
	if !f.Now().Equal(start) {
		t.Fatalf("Now = %v, want %v", f.Now(), start)
	}
	f.Advance(90 * time.Second)
	if want := start.Add(90 * time.Second); !f.Now().Equal(want) {
		t.Fatalf("after Advance Now = %v, want %v", f.Now(), want)
	}
	later := start.Add(time.Hour)
	f.Set(later)
	if !f.Now().Equal(later) {
		t.Fatalf("after Set Now = %v, want %v", f.Now(), later)
	}
}
