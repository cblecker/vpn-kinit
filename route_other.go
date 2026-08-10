//go:build !darwin

// vpn-kinit ships only for darwin: the Makefile and .goreleaser.yml both
// force GOOS=darwin, and the route monitor is written against AF_ROUTE.
// This file exists so that everything portable -- the state machine, the
// klist reader, the krb5.conf parser -- still compiles, and its tests
// still run, on a non-darwin development host.
package main

import (
	"context"
	"log/slog"
)

// defaultInterface mirrors the darwin default so the flag defaults, and
// the tests that pin them, are the same on every host.
const defaultInterface = "utun100"

// routeListen has no routing socket to watch here, so it delivers no
// events and simply waits for shutdown. run() still evaluates once at
// startup; the ticker supplies every trigger after that.
func routeListen(ctx context.Context, _ chan<- struct{}, log *slog.Logger) {
	log.Debug("route monitoring is not available on this platform")
	<-ctx.Done()
}
