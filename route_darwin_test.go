package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPoke covers the coalescing contract the capacity-1 channel encodes:
// route messages arrive in bursts, and the reader must never block, since
// a blocked reader is a missed route event.
func TestPoke(t *testing.T) {
	ch := make(chan struct{}, 1)
	for range 5 {
		poke(ch)
	}
	if len(ch) != 1 {
		t.Errorf("channel holds %d events after 5 pokes, want 1", len(ch))
	}
	<-ch
	select {
	case <-ch:
		t.Error("a second event was queued, want the burst coalesced into one")
	default:
	}
}

func TestSleepCtx(t *testing.T) {
	t.Run("slept fully", func(t *testing.T) {
		if !sleepCtx(context.Background(), time.Millisecond) {
			t.Error("sleepCtx() = false after sleeping the full duration")
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// The backoff must not hold shutdown up for its full duration.
		if sleepCtx(ctx, time.Hour) {
			t.Error("sleepCtx() = true for a cancelled context")
		}
	})
}

func TestReadLoop(t *testing.T) {
	t.Run("every message pokes", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		notify := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() { done <- readLoop(ctx, r, notify) }()

		if _, err := w.WriteString("a route message"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-notify:
		case <-time.After(10 * time.Second):
			t.Fatal("no notification after a message arrived")
		}

		// Shutdown is a Close under a blocked Read, which must read as a
		// clean exit rather than a socket failure worth reopening.
		cancel()
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("readLoop() = %v on shutdown, want nil", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("readLoop did not return after the context was cancelled")
		}
	})

	t.Run("a read failure is reported so the socket is reopened", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()

		notify := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() { done <- readLoop(context.Background(), r, notify) }()

		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Error("readLoop() = nil for a failed read, want the error")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("readLoop did not return after the read failed")
		}
	})
}
