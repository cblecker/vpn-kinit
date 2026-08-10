//go:build darwin

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// defaultInterface is NetBird's default WireGuard interface name on
// this platform.
const defaultInterface = "utun100"

const (
	readBufSize   = 4096
	reopenBackoff = 5 * time.Second
)

// openRouteSocket returns an *os.File wrapping a non-blocking AF_ROUTE
// socket. Non-blocking + os.NewFile registers the fd with the runtime
// poller, so Read parks there and f.Close() safely interrupts it.
func openRouteSocket() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "route"), nil
}

// routeListen owns the route socket lifecycle: open, read until error,
// reopen with backoff, exit on ctx cancellation. Message contents are
// never parsed -- any routing activity is only a hint to re-evaluate
// the interface state, which makes dropped or truncated messages
// harmless.
func routeListen(ctx context.Context, notify chan<- struct{}, log *slog.Logger) {
	for {
		f, err := openRouteSocket()
		if err != nil {
			log.Error("open route socket", "err", err)
			if !sleepCtx(ctx, reopenBackoff) {
				return
			}
			continue
		}
		done := make(chan struct{})
		go func() { // unblocks Read on shutdown
			select {
			case <-ctx.Done():
				_ = f.Close()
			case <-done:
			}
		}()
		err = readLoop(ctx, f, notify)
		close(done)
		_ = f.Close()
		if ctx.Err() != nil {
			return
		}
		log.Warn("route socket read failed, reopening", "err", err)
		poke(notify) // events may have been missed while the socket was down
		if !sleepCtx(ctx, reopenBackoff) {
			return
		}
	}
}

// readLoop pokes for every route message until the socket fails,
// returning the error that ended it so the caller can reopen. A poke is
// not a delivered notification: bursts coalesce in the capacity-1
// channel, which is the point -- one re-evaluation answers a burst as
// well as many would. A read interrupted by ctx being cancelled is a
// clean shutdown, not a failure.
func readLoop(ctx context.Context, f *os.File, notify chan<- struct{}) error {
	buf := make([]byte, readBufSize)
	for {
		_, err := f.Read(buf)
		if ctx.Err() != nil {
			return nil // shutdown: Close() already interrupted us
		}
		if err != nil {
			// ENOBUFS means the kernel dropped events under churn:
			// that in itself signals a change.
			if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EINTR) {
				poke(notify)
				continue
			}
			return err
		}
		poke(notify)
	}
}

// poke signals that something changed, without ever blocking: route
// messages arrive in bursts, and one pending re-evaluation answers all of
// them just as well as a queue would.
func poke(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default: // an evaluate is already pending; coalesce
	}
}

// sleepCtx waits for d, reporting true if it elapsed and false if ctx was
// cancelled first -- so a caller backing off can tell "try again" from
// "we are shutting down".
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
