// Command vpn-kinit watches for a VPN tunnel interface (NetBird's
// WireGuard interface) to come up and runs kinit when it does — and,
// while the tunnel stays up, again shortly before the ticket expires.
// On macOS, kinit acquires tickets using the password stored in the
// login Keychain, and vpn-kinit runs as a per-user LaunchAgent. See
// README.md.
//
// The platform-specific piece is the route monitor that hints when the
// routing table changes (route_darwin.go); everything in this file is
// portable.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	tickerInterval = 60 * time.Second // backstop for missed route events (e.g. across sleep/wake)
	kinitTimeout   = 30 * time.Second
	probeTimeout   = 3 * time.Second
	klistTimeout   = 5 * time.Second
	maxAttempts    = 10 // kinit attempts per up-transition
	krb5ConfPath   = "/etc/krb5.conf"
	kerberosPort   = "88"

	// klistTimestamp is the timestamp layout in `klist --json` output,
	// e.g. "20260810171651", taken as local time to match what plain
	// klist displays.
	klistTimestamp = "20060102150405"

	// fallbackLifetime stands in for the ticket lifetime when the
	// expiry can't be read after a successful kinit, so refreshes
	// degrade to a fixed period instead of firing on every tick.
	fallbackLifetime = 8 * time.Hour
)

func main() {
	ifaceName := flag.String("interface", defaultInterface, "tunnel interface to watch")
	kinitPath := flag.String("kinit", "/usr/bin/kinit", "path to kinit")
	cooldown := flag.Duration("cooldown", 30*time.Second, "minimum interval between kinit attempts")
	refresh := flag.Duration("refresh", time.Hour, "re-run kinit when the ticket has less than this left (0 disables refresh)")
	kdcFlag := flag.String("kdc", "", "KDC to probe for reachability as host[:port] (default: auto-discover from /etc/krb5.conf or DNS SRV)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if *refresh < 0 {
		log.Error("-refresh must be zero or positive", "refresh", *refresh)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := &monitor{
		iface:     *ifaceName,
		kinit:     *kinitPath,
		kinitArgs: flag.Args(), // anything after "--" is passed to kinit
		cooldown:  *cooldown,
		refresh:   *refresh,
		klist:     filepath.Join(filepath.Dir(*kinitPath), "klist"),
		log:       log,
	}
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
	iface     string
	kinit     string
	kinitArgs []string
	cooldown  time.Duration
	refresh   time.Duration // re-kinit when the ticket has less than this left; 0 disables
	klist     string        // path to klist, for reading the ticket expiry
	kdc       string        // host:port to probe; empty means no probe possible (yet)
	realm     string        // for lazy DNS SRV discovery when kdc is empty
	log       *slog.Logger

	wasUp       bool
	done        bool      // kinit succeeded for the current up-period
	attempts    int       // kinit attempts in the current up-period
	lastAttempt time.Time // persists across transitions: flap guard
	expiresAt   time.Time // TGT expiry as of the last klist read; zero = unknown

	// ticketLife caps the refresh margin. It is the true lifetime of
	// the last ticket seen: time-to-expiry measured at our own kinit,
	// or the Issued→Expires span of a ticket read from the cache —
	// never derived from anchors an out-of-band kinit could skew.
	ticketLife time.Duration
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
		if m.refresh > 0 && !m.ticketExpiring(ctx) {
			m.done = true // an existing ticket is still fresh: nothing to do until it nears expiry
			m.log.Info("existing ticket still valid, skipping kinit", "expires", m.expiresAt)
			return
		}
		m.tryKinit(ctx)
	case up && m.wasUp:
		switch {
		case !m.done:
			m.tryKinit(ctx)
		case m.refresh > 0 && m.ticketExpiring(ctx):
			m.log.Info("ticket expiring, refreshing", "expires", m.expiresAt)
			m.done, m.attempts = false, 0
			m.tryKinit(ctx)
		}
	case !up && m.wasUp:
		m.wasUp, m.done = false, false
		m.expiresAt = time.Time{} // may go stale while down: force a klist re-read on the next up
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
	out, err := exec.CommandContext(cctx, m.kinit, m.kinitArgs...).CombinedOutput()
	if err != nil {
		m.log.Error("kinit failed", "attempt", m.attempts, "max", maxAttempts,
			"err", err, "output", strings.TrimSpace(string(out)))
		if m.attempts >= maxAttempts {
			m.log.Error("giving up until next reconnect", "interface", m.iface)
		}
		return
	}
	m.done = true
	if m.refresh <= 0 {
		m.log.Info("kinit succeeded", "attempt", m.attempts)
		return
	}
	exp, issued, ok := m.ticketExpiry(ctx)
	switch {
	case ok && exp.After(time.Now()):
		m.expiresAt = exp
		m.ticketLife = time.Until(exp)
		m.log.Info("kinit succeeded", "attempt", m.attempts, "expires", exp)
		// A ticket acquired moments ago should read as issued about
		// now; a large gap means the klist timestamps are not in
		// local time and refresh timing will be off by that gap.
		if gap := time.Since(issued); !issued.IsZero() && (gap > time.Hour || gap < -time.Hour) {
			m.log.Warn("fresh ticket's issue time is far from now; klist timestamps may not be local time", "issued", issued)
		}
	case ok: // a fresh ticket reading as already expired: timestamps unusable
		m.expiresAt = time.Now().Add(fallbackLifetime)
		m.ticketLife = fallbackLifetime
		m.log.Warn("kinit succeeded but the fresh ticket reads as expired; assuming a lifetime",
			"read", exp, "assumed", fallbackLifetime)
	default:
		m.expiresAt = time.Now().Add(fallbackLifetime)
		m.ticketLife = fallbackLifetime
		m.log.Warn("kinit succeeded but the ticket expiry is unreadable; assuming a lifetime",
			"assumed", fallbackLifetime)
	}
}

// ticketExpiring reports whether the TGT is missing or within the
// refresh margin of expiry. The cached expiry keeps klist from running
// on every tick; it is re-read once the cached time nears, which also
// notices tickets acquired behind vpn-kinit's back (a manual kinit).
func (m *monitor) ticketExpiring(ctx context.Context) bool {
	if time.Until(m.expiresAt) > m.margin() {
		return false
	}
	exp, iss, ok := m.ticketExpiry(ctx)
	if !ok {
		return true // no readable ticket: treat as expired
	}
	m.expiresAt = exp
	if life := exp.Sub(iss); !iss.IsZero() && life > 0 {
		m.ticketLife = life // so the margin cap applies to tickets vpn-kinit didn't acquire
	}
	return time.Until(exp) <= m.margin()
}

// margin returns the effective refresh margin: -refresh, capped at half
// the last observed ticket lifetime so a margin misconfigured to exceed
// the lifetime cannot turn into a kinit-per-cooldown loop.
func (m *monitor) margin() time.Duration {
	if m.ticketLife > 0 && m.ticketLife/2 < m.refresh {
		return m.ticketLife / 2
	}
	return m.refresh
}

// ticketExpiry reads the TGT's expiry and issue time from
// `klist --json`. It prefers the ticket-granting ticket for the cache
// principal's own realm, falling back to the latest-expiring krbtgt.
func (m *monitor) ticketExpiry(ctx context.Context) (expires, issued time.Time, ok bool) {
	cctx, cancel := context.WithTimeout(ctx, klistTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, m.klist, "--json").Output()
	if err != nil {
		var stderr []byte
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = ee.Stderr
		}
		m.log.Debug("klist failed", "klist", m.klist, "err", err,
			"stderr", strings.TrimSpace(string(stderr)))
		return time.Time{}, time.Time{}, false
	}
	var cache struct {
		Principal string `json:"principal"`
		Tickets   []struct {
			Issued    string `json:"Issued"`
			Expires   string `json:"Expires"`
			Principal string `json:"Principal"`
		} `json:"tickets"`
	}
	if err := json.Unmarshal(out, &cache); err != nil {
		m.log.Debug("unparseable klist output", "err", err)
		return time.Time{}, time.Time{}, false
	}
	var tgt string
	if i := strings.LastIndex(cache.Principal, "@"); i >= 0 {
		realm := cache.Principal[i+1:]
		tgt = "krbtgt/" + realm + "@" + realm
	}
	for _, t := range cache.Tickets {
		if !strings.HasPrefix(t.Principal, "krbtgt/") {
			continue
		}
		exp, err := time.ParseInLocation(klistTimestamp, t.Expires, time.Local)
		if err != nil {
			continue
		}
		// A failed parse yields the zero time, which disables the
		// optional issue-time uses (sanity warning, lifetime cap).
		iss, _ := time.ParseInLocation(klistTimestamp, t.Issued, time.Local)
		if t.Principal == tgt {
			return exp, iss, true
		}
		if exp.After(expires) {
			expires, issued, ok = exp, iss, true
		}
	}
	return expires, issued, ok
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
