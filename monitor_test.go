package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The monitor shells out to kinit and klist through fields, so these
// tests fake both as real scripts rather than stubbing the exec call.
// That keeps exec.CommandContext -- exit statuses, stderr capture,
// timeouts -- inside the code under test. The one input with no path
// through a field is the interface state, which is what the ifaceUp seam
// exists for.

// discardLog returns a logger for tests: every path here logs, and none
// of that output is under test.
func discardLog() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// script writes an executable shell script into dir and returns its path.
func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// recorder returns a script that appends a line to a log file on every
// invocation, along with the path of that log, so a test can assert how
// many times -- or whether at all -- the program ran. The path is quoted
// because t.TempDir() builds it from the test name, and the characters it
// lets through include shell metacharacters ("$&(){}~" and a space).
func recorder(t *testing.T, dir, name, body string) (path, calls string) {
	t.Helper()
	calls = filepath.Join(dir, name+".calls")
	return script(t, dir, name, `echo "$@" >> '`+calls+`'`+"\n"+body), calls
}

// callCount reports how many times a recorder script ran.
func callCount(t *testing.T, calls string) int {
	t.Helper()
	data, err := os.ReadFile(calls)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

// stamp renders a time offset from now in klist's timestamp layout.
func stamp(d time.Duration) string {
	return time.Now().Add(d).Format(klistTimestamp)
}

// testRealm is the cache principal's realm in the klist fixtures. Cases
// that need a second realm spell the JSON out inline instead.
const testRealm = "EXAMPLE.COM"

// klistJSON is `klist --json` output holding one krbtgt for testRealm.
func klistJSON(issued, expires string) string {
	return fmt.Sprintf(`{"principal":"me@%[1]s","tickets":[
		{"Issued":%[2]q,"Expires":%[3]q,"Principal":"krbtgt/%[1]s@%[1]s"}]}`,
		testRealm, issued, expires)
}

// klistScript installs a klist printing out, and returns its path and its
// invocation log.
func klistScript(t *testing.T, dir, out string) (path, calls string) {
	t.Helper()
	return recorder(t, dir, "klist", "cat <<'EOJ'\n"+out+"\nEOJ")
}

// noTicket is klist output that parses to no usable ticket, standing in
// for an empty credential cache.
const noTicket = `{"principal":"me@EXAMPLE.COM","tickets":[]}`

// deadAddr is an address nothing can be listening on: binding port 0 has
// the kernel assign an ephemeral port instead, so no socket ever holds
// port 0 itself and the dial always refuses. Taking a real port and
// releasing it would leave a window for another process to claim it
// before the dial, which is a flake rather than a failure.
const deadAddr = "127.0.0.1:0"

// setKrb5Conf points KDC discovery at a fixture for the duration of the
// test; empty content means the file does not exist.
func setKrb5Conf(t *testing.T, content string) {
	t.Helper()
	old := krb5ConfPath
	t.Cleanup(func() { krb5ConfPath = old })
	if content == "" {
		krb5ConfPath = filepath.Join(t.TempDir(), "absent.conf")
		return
	}
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	krb5ConfPath = path
}

// approx reports whether got is within a minute of want, which is as
// precise as these tests can be about durations derived from time.Now().
func approx(got, want time.Duration) bool {
	d := got - want
	return d > -time.Minute && d < time.Minute
}

// TestMargin covers the cap that keeps a -refresh larger than the ticket
// lifetime from making every ticket permanently "expiring", which would
// turn into a kinit per cooldown for as long as the tunnel is up.
func TestMargin(t *testing.T) {
	tests := []struct {
		name          string
		life, refresh time.Duration
		want          time.Duration
	}{
		{"no ticket seen yet, margin as configured", 0, time.Hour, time.Hour},
		{"margin well under the lifetime", 10 * time.Hour, time.Hour, time.Hour},
		{"margin over half the lifetime is capped", time.Hour, 2 * time.Hour, 30 * time.Minute},
		{"margin exactly half the lifetime is kept", 2 * time.Hour, time.Hour, time.Hour},
		{"refresh disabled", 10 * time.Hour, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &monitor{ticketLife: tt.life, refresh: tt.refresh}
			if got := m.margin(); got != tt.want {
				t.Errorf("margin() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTicketExpiry(t *testing.T) {
	var (
		iss    = stamp(0)
		exp8   = stamp(8 * time.Hour)
		exp10  = stamp(10 * time.Hour)
		twoTGT = `{"principal":"me@EXAMPLE.COM","tickets":[
			{"Issued":"` + iss + `","Expires":"` + exp10 + `","Principal":"krbtgt/OTHER.COM@EXAMPLE.COM"},
			{"Issued":"` + iss + `","Expires":"` + exp8 + `","Principal":"krbtgt/EXAMPLE.COM@EXAMPLE.COM"}]}`
		foreignOnly = `{"principal":"me@EXAMPLE.COM","tickets":[
			{"Issued":"` + iss + `","Expires":"` + exp8 + `","Principal":"krbtgt/A.COM@A.COM"},
			{"Issued":"` + iss + `","Expires":"` + exp10 + `","Principal":"krbtgt/B.COM@B.COM"}]}`
	)
	tests := []struct {
		name string
		out  string
		// wantExpires and wantIssued are klist timestamps; an empty
		// wantExpires means the read is expected to fail.
		wantExpires, wantIssued string
	}{
		{
			// A cross-realm TGT can outlive the local one; refreshing on
			// the local one is what keeps the cache usable.
			name:        "the cache principal's own realm wins over a longer-lived foreign TGT",
			out:         twoTGT,
			wantExpires: exp8,
			wantIssued:  iss,
		},
		{
			name:        "no TGT for the own realm falls back to the latest-expiring",
			out:         foreignOnly,
			wantExpires: exp10,
			wantIssued:  iss,
		},
		{
			name: "service tickets are not TGTs",
			out: `{"principal":"me@EXAMPLE.COM","tickets":[
				{"Issued":"` + iss + `","Expires":"` + exp8 + `","Principal":"host/x@EXAMPLE.COM"}]}`,
		},
		{
			name: "an unparseable expiry skips the ticket",
			out:  klistJSON(iss, "not-a-timestamp"),
		},
		{
			// The issue time only feeds optional checks, so losing it
			// must not cost us the expiry.
			name:        "an unparseable issue time still yields the expiry",
			out:         klistJSON("not-a-timestamp", exp8),
			wantExpires: exp8,
		},
		{
			name: "unparseable output",
			out:  "this is not json",
		},
		{
			name: "empty cache",
			out:  noTicket,
		},
		{
			// No principal means no own-realm TGT to prefer; the
			// latest-expiring fallback still applies.
			name:        "no principal in the cache",
			out:         `{"tickets":[{"Issued":"` + iss + `","Expires":"` + exp8 + `","Principal":"krbtgt/E@E"}]}`,
			wantExpires: exp8,
			wantIssued:  iss,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			klist, _ := klistScript(t, dir, tt.out)
			m := &monitor{klist: klist, log: discardLog()}

			exp, issued, ok := m.ticketExpiry(context.Background())
			if ok != (tt.wantExpires != "") {
				t.Fatalf("ticketExpiry() ok = %v, want %v", ok, tt.wantExpires != "")
			}
			if !ok {
				return
			}
			if got := exp.Format(klistTimestamp); got != tt.wantExpires {
				t.Errorf("expires = %s, want %s", got, tt.wantExpires)
			}
			if tt.wantIssued == "" {
				if !issued.IsZero() {
					t.Errorf("issued = %s, want the zero time", issued)
				}
				return
			}
			if got := issued.Format(klistTimestamp); got != tt.wantIssued {
				t.Errorf("issued = %s, want %s", got, tt.wantIssued)
			}
		})
	}
}

// TestTicketExpiryUnrunnable covers klist not being where we looked for
// it, which is the normal case on a host with no Kerberos tooling.
func TestTicketExpiryUnrunnable(t *testing.T) {
	m := &monitor{klist: filepath.Join(t.TempDir(), "klist"), log: discardLog()}
	if _, _, ok := m.ticketExpiry(context.Background()); ok {
		t.Error("ticketExpiry() ok = true for a klist that does not exist")
	}
}

func TestTicketExpiring(t *testing.T) {
	t.Run("a cached expiry beyond the margin does not run klist", func(t *testing.T) {
		dir := t.TempDir()
		klist, calls := klistScript(t, dir, noTicket)
		m := &monitor{
			klist:     klist,
			refresh:   time.Hour,
			expiresAt: time.Now().Add(5 * time.Hour),
			log:       discardLog(),
		}
		if m.ticketExpiring(context.Background()) {
			t.Error("ticketExpiring() = true for a ticket with 5h left")
		}
		// The cache is the whole point: klist on every tick would be a
		// process spawn per minute, forever.
		if n := callCount(t, calls); n != 0 {
			t.Errorf("klist ran %d times, want 0", n)
		}
	})

	t.Run("a cached expiry inside the margin is re-read", func(t *testing.T) {
		dir := t.TempDir()
		klist, calls := klistScript(t, dir, klistJSON(stamp(0), stamp(10*time.Hour)))
		m := &monitor{
			klist:     klist,
			refresh:   time.Hour,
			expiresAt: time.Now().Add(30 * time.Minute),
			log:       discardLog(),
		}
		// A manual kinit behind our back is exactly this: the cached
		// expiry is stale and the cache holds a fresher ticket.
		if m.ticketExpiring(context.Background()) {
			t.Error("ticketExpiring() = true after re-reading a fresh ticket")
		}
		if n := callCount(t, calls); n != 1 {
			t.Errorf("klist ran %d times, want 1", n)
		}
		if got := time.Until(m.expiresAt); !approx(got, 10*time.Hour) {
			t.Errorf("expiresAt is %s away, want ~10h", got)
		}
		if !approx(m.ticketLife, 10*time.Hour) {
			t.Errorf("ticketLife = %s, want ~10h", m.ticketLife)
		}
	})

	t.Run("a ticket inside the margin is expiring", func(t *testing.T) {
		dir := t.TempDir()
		klist, _ := klistScript(t, dir, klistJSON(stamp(-9*time.Hour), stamp(30*time.Minute)))
		m := &monitor{klist: klist, refresh: time.Hour, log: discardLog()}
		if !m.ticketExpiring(context.Background()) {
			t.Error("ticketExpiring() = false for a ticket with 30m left")
		}
	})

	t.Run("no readable ticket counts as expiring", func(t *testing.T) {
		m := &monitor{klist: filepath.Join(t.TempDir(), "klist"), refresh: time.Hour, log: discardLog()}
		if !m.ticketExpiring(context.Background()) {
			t.Error("ticketExpiring() = false with no readable ticket")
		}
	})
}

func TestTryKinit(t *testing.T) {
	ctx := context.Background()

	t.Run("success records the expiry and the args reach kinit", func(t *testing.T) {
		dir := t.TempDir()
		kinit, kinitCalls := recorder(t, dir, "kinit", "exit 0")
		klist, _ := klistScript(t, dir, klistJSON(stamp(0), stamp(10*time.Hour)))
		m := &monitor{
			kinit:     kinit,
			kinitArgs: []string{"-kt", "/path/to/keytab", "user@REALM"},
			klist:     klist,
			cooldown:  30 * time.Second,
			refresh:   time.Hour,
			log:       discardLog(),
		}
		m.tryKinit(ctx)

		if !m.done {
			t.Error("done = false after a successful kinit")
		}
		if m.attempts != 1 {
			t.Errorf("attempts = %d, want 1", m.attempts)
		}
		if !approx(m.ticketLife, 10*time.Hour) {
			t.Errorf("ticketLife = %s, want ~10h", m.ticketLife)
		}
		if got := time.Until(m.expiresAt); !approx(got, 10*time.Hour) {
			t.Errorf("expiresAt is %s away, want ~10h", got)
		}
		args, err := os.ReadFile(kinitCalls)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(args)); got != "-kt /path/to/keytab user@REALM" {
			t.Errorf("kinit args = %q, want the passthrough args", got)
		}

		// Cooldown: a second trigger moments later must not re-run kinit.
		m.tryKinit(ctx)
		if n := callCount(t, kinitCalls); n != 1 {
			t.Errorf("kinit ran %d times within the cooldown, want 1", n)
		}
		if m.attempts != 1 {
			t.Errorf("attempts = %d after a rate-limited trigger, want 1", m.attempts)
		}
	})

	t.Run("failures stop at the attempt cap", func(t *testing.T) {
		dir := t.TempDir()
		kinit, kinitCalls := recorder(t, dir, "kinit", "echo 'kinit: no such realm' >&2\nexit 1")
		m := &monitor{kinit: kinit, klist: filepath.Join(dir, "klist"), refresh: time.Hour, log: discardLog()}

		// Cooldown is zero, so only the cap can stop this.
		for range maxAttempts + 5 {
			m.tryKinit(ctx)
		}
		if m.attempts != maxAttempts {
			t.Errorf("attempts = %d, want the cap of %d", m.attempts, maxAttempts)
		}
		if n := callCount(t, kinitCalls); n != maxAttempts {
			t.Errorf("kinit ran %d times, want %d", n, maxAttempts)
		}
		if m.done {
			t.Error("done = true after only failures")
		}
	})

	t.Run("an unreadable expiry assumes a lifetime", func(t *testing.T) {
		dir := t.TempDir()
		kinit, _ := recorder(t, dir, "kinit", "exit 0")
		m := &monitor{kinit: kinit, klist: filepath.Join(dir, "klist"), refresh: time.Hour, log: discardLog()}
		m.tryKinit(ctx)

		if !m.done {
			t.Error("done = false after a successful kinit")
		}
		// Without this the expiry stays zero, every tick reads as
		// expiring, and the refresh degrades to a kinit per cooldown.
		if m.ticketLife != fallbackLifetime {
			t.Errorf("ticketLife = %s, want the %s fallback", m.ticketLife, fallbackLifetime)
		}
		if got := time.Until(m.expiresAt); !approx(got, fallbackLifetime) {
			t.Errorf("expiresAt is %s away, want ~%s", got, fallbackLifetime)
		}
	})

	t.Run("a fresh ticket reading as expired assumes a lifetime", func(t *testing.T) {
		dir := t.TempDir()
		kinit, _ := recorder(t, dir, "kinit", "exit 0")
		// Timestamps in some other timezone can read as long past.
		klist, _ := klistScript(t, dir, klistJSON(stamp(-20*time.Hour), stamp(-10*time.Hour)))
		m := &monitor{kinit: kinit, klist: klist, refresh: time.Hour, log: discardLog()}
		m.tryKinit(ctx)

		if m.ticketLife != fallbackLifetime {
			t.Errorf("ticketLife = %s, want the %s fallback", m.ticketLife, fallbackLifetime)
		}
		if !m.expiresAt.After(time.Now()) {
			t.Errorf("expiresAt = %s, want a time in the future", m.expiresAt)
		}
	})

	t.Run("an unreachable KDC costs neither an attempt nor the cooldown", func(t *testing.T) {
		dir := t.TempDir()
		kinit, kinitCalls := recorder(t, dir, "kinit", "exit 0")
		m := &monitor{
			kinit:    kinit,
			klist:    filepath.Join(dir, "klist"),
			kdc:      deadAddr,
			cooldown: time.Hour,
			refresh:  time.Hour,
			log:      discardLog(),
		}
		m.tryKinit(ctx)

		if n := callCount(t, kinitCalls); n != 0 {
			t.Errorf("kinit ran %d times behind an unreachable KDC, want 0", n)
		}
		// Probes are free: burning attempts on them would exhaust the
		// cap before the tunnel finished coming up.
		if m.attempts != 0 {
			t.Errorf("attempts = %d, want 0", m.attempts)
		}
		if !m.lastAttempt.IsZero() {
			t.Errorf("lastAttempt = %s, want the zero time", m.lastAttempt)
		}
	})

	t.Run("refresh disabled skips the expiry read", func(t *testing.T) {
		dir := t.TempDir()
		kinit, _ := recorder(t, dir, "kinit", "exit 0")
		klist, klistCalls := klistScript(t, dir, klistJSON(stamp(0), stamp(10*time.Hour)))
		m := &monitor{kinit: kinit, klist: klist, refresh: 0, log: discardLog()}
		m.tryKinit(ctx)

		if !m.done {
			t.Error("done = false after a successful kinit")
		}
		if n := callCount(t, klistCalls); n != 0 {
			t.Errorf("klist ran %d times with refresh disabled, want 0", n)
		}
		if !m.expiresAt.IsZero() {
			t.Errorf("expiresAt = %s, want the zero time", m.expiresAt)
		}
	})
}

// harness drives evaluate with a fake interface, kinit, and klist.
type harness struct {
	m          *monitor
	up         bool
	kinitCalls string
}

func newHarness(t *testing.T, klistOut string) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{}
	kinit, calls := recorder(t, dir, "kinit", "exit 0")
	klist, _ := klistScript(t, dir, klistOut)
	h.kinitCalls = calls
	h.m = &monitor{
		iface:   "tun-test0",
		kinit:   kinit,
		klist:   klist,
		refresh: time.Hour,
		log:     discardLog(),
		ifaceUp: func(string) bool { return h.up },
	}
	return h
}

func (h *harness) kinits(t *testing.T) int {
	t.Helper()
	return callCount(t, h.kinitCalls)
}

func TestEvaluate(t *testing.T) {
	ctx := context.Background()

	t.Run("an interface that is down does nothing", func(t *testing.T) {
		h := newHarness(t, noTicket)
		h.m.evaluate(ctx)
		if n := h.kinits(t); n != 0 {
			t.Errorf("kinit ran %d times with the interface down, want 0", n)
		}
		if h.m.wasUp {
			t.Error("wasUp = true with the interface down")
		}
	})

	t.Run("coming up with no ticket runs kinit once", func(t *testing.T) {
		h := newHarness(t, noTicket)
		h.up = true
		h.m.evaluate(ctx)
		if n := h.kinits(t); n != 1 {
			t.Fatalf("kinit ran %d times on the up-transition, want 1", n)
		}
		if !h.m.wasUp || !h.m.done {
			t.Errorf("wasUp = %v, done = %v, want both true", h.m.wasUp, h.m.done)
		}
		// The steady state: triggers keep arriving every minute and must
		// not each cost a kinit.
		h.m.evaluate(ctx)
		if n := h.kinits(t); n != 1 {
			t.Errorf("kinit ran %d times while already done, want 1", n)
		}
	})

	t.Run("coming up with a valid ticket skips kinit", func(t *testing.T) {
		h := newHarness(t, klistJSON(stamp(0), stamp(10*time.Hour)))
		h.up = true
		h.m.evaluate(ctx)
		// A daemon restart or a brief flap should not burn a kinit.
		if n := h.kinits(t); n != 0 {
			t.Errorf("kinit ran %d times with a fresh ticket, want 0", n)
		}
		if !h.m.done {
			t.Error("done = false, want the up-period marked satisfied")
		}
		if got := time.Until(h.m.expiresAt); !approx(got, 10*time.Hour) {
			t.Errorf("expiresAt is %s away, want ~10h", got)
		}
	})

	t.Run("a failed kinit is retried on the next trigger", func(t *testing.T) {
		dir := t.TempDir()
		kinit, calls := recorder(t, dir, "kinit", "exit 1")
		klist, _ := klistScript(t, dir, noTicket)
		up := true
		m := &monitor{
			iface: "tun-test0", kinit: kinit, klist: klist,
			refresh: time.Hour, log: discardLog(),
			ifaceUp: func(string) bool { return up },
		}
		m.evaluate(ctx)
		m.evaluate(ctx)
		if n := callCount(t, calls); n != 2 {
			t.Errorf("kinit ran %d times, want a retry on the second trigger", n)
		}
		if m.done {
			t.Error("done = true after failures")
		}
	})

	t.Run("an expiring ticket starts a fresh round", func(t *testing.T) {
		h := newHarness(t, klistJSON(stamp(-9*time.Hour), stamp(30*time.Minute)))
		// Steady state, one attempt already spent, ticket nearly gone.
		h.up = true
		h.m.wasUp, h.m.done, h.m.attempts = true, true, 4
		h.m.expiresAt = time.Now().Add(30 * time.Minute)

		h.m.evaluate(ctx)
		if n := h.kinits(t); n != 1 {
			t.Errorf("kinit ran %d times for an expiring ticket, want 1", n)
		}
		// The refresh is a new round, so the previous round's attempts
		// must not count against its cap.
		if h.m.attempts != 1 {
			t.Errorf("attempts = %d, want the counter reset to 1", h.m.attempts)
		}
	})

	t.Run("going down resets the up-period state", func(t *testing.T) {
		h := newHarness(t, klistJSON(stamp(0), stamp(10*time.Hour)))
		h.up = true
		h.m.evaluate(ctx)
		h.up = false
		h.m.evaluate(ctx)

		if h.m.wasUp || h.m.done {
			t.Errorf("wasUp = %v, done = %v, want both false", h.m.wasUp, h.m.done)
		}
		// The cached expiry can go stale while the tunnel is down, so
		// the next up-transition has to re-read it.
		if !h.m.expiresAt.IsZero() {
			t.Errorf("expiresAt = %s, want the zero time", h.m.expiresAt)
		}
	})

	t.Run("refresh disabled leaves an up tunnel alone", func(t *testing.T) {
		h := newHarness(t, klistJSON(stamp(-9*time.Hour), stamp(time.Minute)))
		h.m.refresh = 0
		h.up = true
		h.m.evaluate(ctx)
		h.m.evaluate(ctx)
		// Even with the ticket about to expire, -refresh 0 means purely
		// edge-triggered behaviour.
		if n := h.kinits(t); n != 1 {
			t.Errorf("kinit ran %d times with refresh disabled, want 1", n)
		}
	})
}

func TestKDCReachable(t *testing.T) {
	t.Run("a listening KDC is reachable", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		m := &monitor{kdc: l.Addr().String(), log: discardLog()}
		if !m.kdcReachable() {
			t.Errorf("kdcReachable() = false for a listening socket at %s", l.Addr())
		}
	})

	t.Run("a closed port is not reachable", func(t *testing.T) {
		m := &monitor{kdc: deadAddr, log: discardLog()}
		if m.kdcReachable() {
			t.Error("kdcReachable() = true for a closed port")
		}
	})

	t.Run("no KDC gates nothing", func(t *testing.T) {
		// Discovery found nothing, so kinit has to run unguarded rather
		// than never run at all.
		m := &monitor{log: discardLog()}
		if !m.kdcReachable() {
			t.Error("kdcReachable() = false with no KDC known")
		}
	})

	t.Run("a failed DNS SRV lookup gates nothing either", func(t *testing.T) {
		// .invalid is reserved (RFC 2606), so this resolves nowhere on
		// any host, with or without a working resolver.
		m := &monitor{realm: "no-such-realm.invalid", log: discardLog()}
		if !m.kdcReachable() {
			t.Error("kdcReachable() = false when SRV discovery found nothing")
		}
		if m.kdc != "" {
			t.Errorf("kdc = %q, want it left empty for the next attempt", m.kdc)
		}
	})
}

func TestDiscoverKDC(t *testing.T) {
	const conf = `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = {
		kdc = kdc.example.com
	}
`
	tests := []struct {
		name               string
		flag, krb5         string
		wantKDC, wantRealm string
	}{
		{
			name:    "the flag wins and gets the default port",
			flag:    "kdc.example.com",
			krb5:    conf,
			wantKDC: "kdc.example.com:88",
		},
		{
			name:    "an explicit port in the flag is kept",
			flag:    "kdc.example.com:8888",
			wantKDC: "kdc.example.com:8888",
		},
		{
			name:      "krb5.conf supplies the first kdc",
			krb5:      conf,
			wantKDC:   "kdc.example.com:88",
			wantRealm: "EXAMPLE.COM",
		},
		{
			// The realm is still worth keeping: DNS SRV is tried later,
			// once the tunnel can resolve it.
			name:      "a realm with no kdc entry defers to DNS SRV",
			krb5:      "[libdefaults]\n\tdefault_realm = EXAMPLE.COM\n",
			wantRealm: "EXAMPLE.COM",
		},
		{
			name: "no krb5.conf at all",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setKrb5Conf(t, tt.krb5)
			m := &monitor{log: discardLog()}
			m.discoverKDC(tt.flag)
			if m.kdc != tt.wantKDC {
				t.Errorf("kdc = %q, want %q", m.kdc, tt.wantKDC)
			}
			if m.realm != tt.wantRealm {
				t.Errorf("realm = %q, want %q", m.realm, tt.wantRealm)
			}
		})
	}
}

func TestWithDefaultPort(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"a bare hostname takes the Kerberos port", "kdc.example.com", "kdc.example.com:88"},
		{"an explicit port is kept", "kdc.example.com:8888", "kdc.example.com:8888"},
		{"a bare IPv4 address takes the Kerberos port", "10.0.0.1", "10.0.0.1:88"},
		{"a bare IPv6 address is bracketed", "::1", "[::1]:88"},
		{"a bracketed IPv6 address with a port is kept", "[::1]:8888", "[::1]:8888"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withDefaultPort(tt.in); got != tt.want {
				t.Errorf("withDefaultPort(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInterfaceUp(t *testing.T) {
	ifis, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp != 0 {
			name = ifi.Name
			break
		}
	}
	if name == "" {
		t.Skip("no interface is up on this host")
	}
	if !interfaceUp(name) {
		t.Errorf("interfaceUp(%q) = false for an interface the kernel reports as up", name)
	}
	// A tunnel that is not connected has no interface at all, which is
	// the down state rather than an error.
	if interfaceUp("tun-does-not-exist0") {
		t.Error("interfaceUp() = true for an interface that does not exist")
	}
}

// TestRunShutdown covers the signal path: run has to return so that
// deferred cleanup happens and launchd sees a clean exit.
func TestRunShutdown(t *testing.T) {
	setKrb5Conf(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dir := t.TempDir()
	cfg := &config{iface: "tun-does-not-exist0", kinit: script(t, dir, "kinit", "exit 0"), refresh: time.Hour}

	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx, cfg, discardLog())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after the context was cancelled")
	}
}
