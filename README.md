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

- macOS with a Go toolchain (`brew install go`)
- A working `/etc/krb5.conf` (with `default_realm`, and ideally `kdc`
  entries for the realm)
- Your Kerberos password saved in the login Keychain — run `kinit`
  once interactively and let it store the password

## Install

```sh
make install
```

This builds the binary to `~/.local/bin/vpn-kinit` (override with
`PREFIX=...`), renders the LaunchAgent plist into
`~/Library/LaunchAgents/com.cblecker.vpn-kinit.plist`, and loads it via
`launchctl bootstrap`. Re-run `make install` after any change — it
reloads the agent. `make uninstall` removes everything.

## Configuration

Flags (set in the `ProgramArguments` array of
`LaunchAgents/com.cblecker.vpn-kinit.plist.in`, then re-run
`make install`):

| Flag         | Default          | Meaning                                          |
|--------------|------------------|--------------------------------------------------|
| `-interface` | `utun100`        | Tunnel interface to watch                        |
| `-kinit`     | `/usr/bin/kinit` | Path to kinit                                    |
| `-cooldown`  | `30s`            | Minimum interval between kinit attempts          |
| `-kdc`       | auto             | KDC to probe as `host[:port]`                    |
| `-debug`     | off              | Debug logging (including failed KDC probes)      |

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

- Logs: `~/Library/Logs/vpn-kinit.log`
- Agent state: `launchctl print gui/$(id -u)/com.cblecker.vpn-kinit`
- Tickets: `klist`
- kinit failing with the tunnel up usually means no Keychain password
  item — run `kinit` once interactively. Note this must run as a
  LaunchAgent (not a LaunchDaemon) to access the login Keychain.
- Building on non-macOS hosts: the code is darwin-only; use
  `GOOS=darwin go build` (the Makefile does this automatically).
