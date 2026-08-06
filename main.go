//go:build darwin

// Command vpn-kinit watches for a WireGuard utun interface (NetBird's
// tunnel) to come up and runs kinit once per up-transition, acquiring
// Kerberos tickets using the password stored in the login Keychain.
// It is designed to run as a per-user LaunchAgent. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tickerInterval = 60 * time.Second // backstop for missed route events (e.g. across sleep/wake)
	kinitTimeout   = 30 * time.Second
	probeTimeout   = 3 * time.Second
	maxAttempts    = 10 // kinit attempts per up-transition
	readBufSize    = 4096
	reopenBackoff  = 5 * time.Second
	krb5ConfPath   = "/etc/krb5.conf"
	kerberosPort   = "88"
)

func main() {
	ifaceName := flag.String("interface", "utun100", "tunnel interface to watch")
	kinitPath := flag.String("kinit", "/usr/bin/kinit", "path to kinit")
	cooldown := flag.Duration("cooldown", 30*time.Second, "minimum interval between kinit attempts")
	kdcFlag := flag.String("kdc", "", "KDC to probe for reachability as host[:port] (default: auto-discover from /etc/krb5.conf or DNS SRV)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := &monitor{iface: *ifaceName, kinit: *kinitPath, cooldown: *cooldown, log: log}
	m.discoverKDC(*kdcFlag)

	events := make(chan struct{}, 1) // capacity 1: bursts coalesce
	go routeListen(ctx, events, log)

	log.Info("vpn-kinit started", "interface", m.iface, "kinit", m.kinit)
	m.evaluate(ctx) // interface may already be up at startup

	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return
		case <-events:
			m.evaluate(ctx)
		case <-ticker.C:
			m.evaluate(ctx)
		}
	}
}

// monitor holds the edge-detection state machine. All fields are only
// accessed from the main goroutine.
type monitor struct {
	iface    string
	kinit    string
	cooldown time.Duration
	kdc      string // host:port to probe; empty means no probe possible (yet)
	realm    string // for lazy DNS SRV discovery when kdc is empty
	log      *slog.Logger

	wasUp       bool
	done        bool      // kinit succeeded for the current up-period
	attempts    int       // kinit attempts in the current up-period
	lastAttempt time.Time // persists across transitions: flap guard
}

// discoverKDC resolves which KDC to probe before running kinit:
// explicit flag, then /etc/krb5.conf, then (lazily, at probe time)
// DNS SRV. With no KDC found kinit runs unguarded.
func (m *monitor) discoverKDC(flagVal string) {
	if flagVal != "" {
		m.kdc = withDefaultPort(flagVal)
		m.log.Info("probing KDC from flag", "kdc", m.kdc)
		return
	}
	realm, kdcs := parseKrb5Conf(krb5ConfPath)
	m.realm = realm
	if len(kdcs) > 0 {
		m.kdc = withDefaultPort(kdcs[0])
		m.log.Info("probing KDC from krb5.conf", "kdc", m.kdc, "realm", realm)
		return
	}
	if realm != "" {
		m.log.Info("no kdc entry in krb5.conf, will try DNS SRV", "realm", realm)
		return
	}
	m.log.Warn("no KDC discovered; kinit will run without a reachability probe")
}

func interfaceUp(name string) bool {
	ifi, err := net.InterfaceByName(name)
	return err == nil && ifi.Flags&net.FlagUp != 0
}

func (m *monitor) evaluate(ctx context.Context) {
	up := interfaceUp(m.iface)
	switch {
	case up && !m.wasUp:
		m.wasUp, m.done, m.attempts = true, false, 0
		m.log.Info("interface up", "interface", m.iface)
		m.tryKinit(ctx)
	case up && m.wasUp:
		if !m.done {
			m.tryKinit(ctx)
		}
	case !up && m.wasUp:
		m.wasUp, m.done = false, false
		m.log.Info("interface down", "interface", m.iface)
	}
}

func (m *monitor) tryKinit(ctx context.Context) {
	if m.attempts >= maxAttempts {
		return // gave up for this up-period; logged when the cap was hit
	}
	if time.Since(m.lastAttempt) < m.cooldown {
		return // rate-limited; a later trigger (ticker at worst) retries
	}
	if !m.kdcReachable() {
		return // probe failures are free: no attempt or cooldown consumed
	}
	m.attempts++
	m.lastAttempt = time.Now()

	cctx, cancel := context.WithTimeout(ctx, kinitTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, m.kinit).CombinedOutput()
	if err != nil {
		m.log.Error("kinit failed", "attempt", m.attempts, "max", maxAttempts,
			"err", err, "output", strings.TrimSpace(string(out)))
		if m.attempts >= maxAttempts {
			m.log.Error("giving up until next reconnect", "interface", m.iface)
		}
		return
	}
	m.done = true
	m.log.Info("kinit succeeded", "attempt", m.attempts)
}

// kdcReachable reports whether the KDC accepts TCP connections. When no
// KDC is known it tries DNS SRV discovery first (the realm's DNS may
// only resolve once the tunnel is up), and gates nothing if that fails.
func (m *monitor) kdcReachable() bool {
	if m.kdc == "" && m.realm != "" {
		if kdc := lookupKDCSRV(m.realm); kdc != "" {
			m.kdc = kdc
			m.log.Info("probing KDC from DNS SRV", "kdc", m.kdc, "realm", m.realm)
		}
	}
	if m.kdc == "" {
		return true
	}
	conn, err := net.DialTimeout("tcp", m.kdc, probeTimeout)
	if err != nil {
		m.log.Debug("KDC not reachable yet", "kdc", m.kdc, "err", err)
		return false
	}
	_ = conn.Close()
	return true
}

func lookupKDCSRV(realm string) string {
	_, addrs, err := net.LookupSRV("kerberos", "tcp", realm)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	target := strings.TrimSuffix(addrs[0].Target, ".")
	return net.JoinHostPort(target, strconv.Itoa(int(addrs[0].Port)))
}

func withDefaultPort(hostport string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, kerberosPort)
}

// parseKrb5Conf extracts default_realm and that realm's kdc entries.
// It understands just enough of the krb5.conf format for this purpose:
// comments, [section] headers, key = value lines, and one level of
// braced realm blocks. include/includedir directives are not followed.
func parseKrb5Conf(path string) (realm string, kdcs []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	var section, curRealm string
	realmKDCs := make(map[string][]string)
	for line := range strings.Lines(string(data)) {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, curRealm = strings.ToLower(line[1:len(line)-1]), ""
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch section {
		case "libdefaults":
			if ok && strings.EqualFold(key, "default_realm") {
				realm = value
			}
		case "realms":
			switch {
			case curRealm == "":
				if ok && value == "{" {
					curRealm = key
				}
			case line == "}":
				curRealm = ""
			case ok && strings.EqualFold(key, "kdc"):
				realmKDCs[curRealm] = append(realmKDCs[curRealm], value)
			}
		}
	}
	return realm, realmKDCs[realm]
}

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

func poke(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default: // an evaluate is already pending; coalesce
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
