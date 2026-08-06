# CLAUDE.md

macOS daemon that runs kinit when the NetBird VPN tunnel comes up. See
README.md for architecture, install, and usage.

## Commands

| Command | Purpose |
|---------|---------|
| `make build` | Cross-compile `bin/vpn-kinit` (GOOS=darwin is forced, works on any host) |
| `make check` | `go vet` + gofmt check |
| `make install` | Build, install, and (re)bootstrap the LaunchAgent (macOS only) |

## Conventions

- When addressing automated review feedback on a PR (Copilot, CodeRabbit): wait until
  every reviewer has finished reviewing the current head, then push fixes for all
  findings as a single commit — one push per review round, not one per reviewer.
  CodeRabbit auto-reviews every push and its incremental reviews are rate-limited,
  so per-reviewer pushes burn the allowance on intermediate states
