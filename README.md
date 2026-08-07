# vpn-kinit

A tiny macOS daemon that runs `kinit` automatically when a
[NetBird](https://github.com/netbirdio/netbird) VPN tunnel comes up.

NetBird has no post-connect hook or script-execution feature
([netbirdio/netbird#3591](https://github.com/netbirdio/netbird/issues/3591)),
so there is no built-in way to acquire Kerberos tickets when the VPN
connects. vpn-kinit fills that gap: it watches for the NetBird WireGuard
interface (`utun100` by default) to appear, waits until the KDC is
actually reachable through the tunnel, and then runs `/usr/bin/kinit` —
which on macOS acquires tickets using the password stored in the login
Keychain (per `/etc/krb5.conf`).

It idles blocked on a kernel routing socket: zero CPU and a couple of
megabytes of memory.

## Prerequisites

- macOS
- A working `/etc/krb5.conf` (with `default_realm`, and ideally `kdc`
  entries for the realm)
- Your Kerberos password saved in the login Keychain — run `kinit`
  once interactively and let it store the password

## Install

```sh
brew install cblecker/tap/vpn-kinit
brew services start cblecker/tap/vpn-kinit
```

Run `brew services` without `sudo`: that starts vpn-kinit as a
LaunchAgent in your login session, which is what gives it access to the
login Keychain. As a root-owned LaunchDaemon it cannot read the stored
password.

To upgrade, and to uninstall:

```sh
brew upgrade cblecker/tap/vpn-kinit
brew services restart cblecker/tap/vpn-kinit

brew services stop cblecker/tap/vpn-kinit
brew uninstall cblecker/tap/vpn-kinit
```

The Homebrew service runs vpn-kinit with no flags, so it uses the
defaults below (interface `utun100`, KDC auto-discovered from
`/etc/krb5.conf` or DNS SRV). That covers a stock NetBird install; if
you need different flags, install from source instead.

### From source

For development, or when you need to pass flags:

```sh
make install
```

This requires a Go toolchain (`brew install go`). It builds the binary
to `~/.local/bin/vpn-kinit` (override with `PREFIX=...`), renders the
LaunchAgent plist into
`~/Library/LaunchAgents/com.cblecker.vpn-kinit.plist`, and loads it via
`launchctl bootstrap`. Re-run `make install` after any change — it
reloads the agent. `make uninstall` removes everything. Stop the
Homebrew service first if you have one running, so the two copies don't
both fire.

Other targets: `make build` (cross-compiles for darwin from any host)
and `make check` (`go vet` + gofmt).

## Configuration

The Homebrew service passes no flags, so it runs on the defaults below.
To change them, install from source and edit the `ProgramArguments`
array of `LaunchAgents/com.cblecker.vpn-kinit.plist.in`, then re-run
`make install`.

| Flag         | Default          | Meaning                                          |
|--------------|------------------|--------------------------------------------------|
| `-interface` | `utun100`        | Tunnel interface to watch                        |
| `-kinit`     | `/usr/bin/kinit` | Path to kinit                                    |
| `-cooldown`  | `30s`            | Minimum interval between kinit attempts          |
| `-kdc`       | auto             | KDC to probe as `host[:port]`                    |
| `-debug`     | off              | Debug logging (including failed KDC probes)      |

Anything after a `--` separator is passed through as arguments to
kinit — useful for keytab-based setups (e.g.
`vpn-kinit -- -kt /path/to/keytab user@REALM`). On macOS with the
password in the login Keychain, no arguments are needed.

If you run NetBird with a custom `--interface-name`, set `-interface`
to match. The KDC to probe is auto-discovered from `/etc/krb5.conf`
(`default_realm` + that realm's `kdc` entries), falling back to a DNS
SRV lookup of `_kerberos._tcp.<realm>`; use `-kdc` to override. If no
KDC can be discovered, kinit simply runs without the reachability
gate.

## How it works

Three trigger sources feed one edge-detecting state machine:

1. an `AF_ROUTE` routing socket — any routing-table activity (such as
   NetBird bringing the tunnel up) prompts a re-check of the interface;
2. a 60-second ticker — a backstop for events missed across sleep/wake,
   where the routing socket alone is known to be unreliable
   ([netbirdio/netbird#2196](https://github.com/netbirdio/netbird/issues/2196));
3. a startup check — covers the daemon starting while the VPN is
   already connected.

On each trigger it checks whether the interface exists and is up. On a
down→up transition it probes the KDC over TCP (port 88) and, once
reachable, runs `kinit`. A failed kinit is retried on later triggers
(at most 10 attempts per connect, rate-limited by `-cooldown`); failed
KDC probes are free and never count as attempts. Nothing runs again
until the tunnel goes down and comes back up.

Route messages are never parsed — they are only a hint to re-check
interface state — so kernel-dropped or truncated messages are
harmless. If the routing socket fails it is reopened automatically.

Known limitation: vpn-kinit is edge-triggered, so a VPN session that
outlives the ticket lifetime gets no automatic re-kinit. A possible
future enhancement is subscribing to the NetBird daemon's
`SubscribeStatus` gRPC stream for exact connection-state semantics,
at the cost of depending on NetBird's internal API.

## Troubleshooting

### Logs

vpn-kinit logs to stderr; where that lands depends on how you installed
it.

| Install | Log file |
|---------|----------|
| Homebrew | `$(brew --prefix)/var/log/vpn-kinit.log` |
| `make install` | `~/Library/Logs/vpn-kinit.log` |

```sh
# Homebrew
tail -f "$(brew --prefix)/var/log/vpn-kinit.log"

# make install
tail -f ~/Library/Logs/vpn-kinit.log
```

Both install methods send stdout and stderr to the same file. Logged at
the default level: startup (with the interface and kinit path), which
KDC was discovered and from where, every interface up/down transition,
and every kinit attempt — failures include the attempt number and
kinit's combined output. Add `-debug` to also log KDC probe failures,
which is the case to look at when the interface comes up but kinit
never runs.

Since the Homebrew service takes no flags, the way to get debug output
from a Homebrew install is to stop the service and run it in the
foreground, where the same log goes straight to your terminal:

```sh
brew services stop cblecker/tap/vpn-kinit
"$(brew --prefix)/bin/vpn-kinit" -debug   # ^C when done
brew services start cblecker/tap/vpn-kinit
```

The explicit path matters if you also have a source install: a bare
`vpn-kinit` would resolve to whichever copy comes first on `PATH`.

### Other checks

- Service state (Homebrew): `brew services info cblecker/tap/vpn-kinit`
- Agent state (`make install`):
  `launchctl print gui/$(id -u)/com.cblecker.vpn-kinit`
- Tickets: `klist`
- kinit failing with the tunnel up usually means no Keychain password
  item — run `kinit` once interactively. Note this must run as a
  LaunchAgent (not a LaunchDaemon) to access the login Keychain.
- Building on non-macOS hosts: the code is darwin-only; use
  `GOOS=darwin go build` (the Makefile does this automatically).
