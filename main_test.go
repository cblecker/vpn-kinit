package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// parse is parseFlags with the diagnostics captured instead of discarded.
func parse(t *testing.T, args ...string) (*config, string, error) {
	t.Helper()
	var out strings.Builder
	cfg, err := parseFlags("vpn-kinit", args, &out)
	return cfg, out.String(), err
}

// TestParseFlagsDefaults pins the defaults documented in README.md.
func TestParseFlagsDefaults(t *testing.T) {
	cfg, out, err := parse(t)
	if err != nil {
		t.Fatalf("parseFlags() error = %v, output %q", err, out)
	}
	if cfg.iface != defaultInterface {
		t.Errorf("iface = %q, want %q", cfg.iface, defaultInterface)
	}
	if cfg.kinit != "/usr/bin/kinit" {
		t.Errorf("kinit = %q, want /usr/bin/kinit", cfg.kinit)
	}
	if cfg.cooldown != 30*time.Second {
		t.Errorf("cooldown = %s, want 30s", cfg.cooldown)
	}
	if cfg.refresh != time.Hour {
		t.Errorf("refresh = %s, want 1h", cfg.refresh)
	}
	if cfg.kdc != "" {
		t.Errorf("kdc = %q, want empty", cfg.kdc)
	}
	if cfg.debug {
		t.Error("debug = true, want false")
	}
	if len(cfg.kinitArgs) != 0 {
		t.Errorf("kinitArgs = %q, want none", cfg.kinitArgs)
	}
	if out != "" {
		t.Errorf("unexpected output %q", out)
	}
}

// TestParseFlagsPassthrough covers the "--" contract from README.md: the
// arguments are themselves dash-prefixed and must reach kinit untouched
// rather than being parsed as vpn-kinit's own flags.
func TestParseFlagsPassthrough(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		want  []string
		debug bool
	}{
		{
			name: "keytab args",
			args: []string{"--", "-kt", "/path/to/keytab", "user@REALM"},
			want: []string{"-kt", "/path/to/keytab", "user@REALM"},
		},
		{
			name: "after our own flags",
			args: []string{"-debug", "--", "-kt", "/path/to/keytab"},
			want: []string{"-kt", "/path/to/keytab"},
			// -debug before "--" is ours...
			debug: true,
		},
		{
			// ...but the same spelling after "--" belongs to kinit.
			name: "our flag names are not stolen back",
			args: []string{"--", "-debug"},
			want: []string{"-debug"},
		},
		{
			name: "bare principal",
			args: []string{"--", "user@REALM"},
			want: []string{"user@REALM"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, out, err := parse(t, tt.args...)
			if err != nil {
				t.Fatalf("parseFlags(%q) error = %v, output %q", tt.args, err, out)
			}
			if !slices.Equal(cfg.kinitArgs, tt.want) {
				t.Errorf("kinitArgs = %q, want %q", cfg.kinitArgs, tt.want)
			}
			if cfg.debug != tt.debug {
				t.Errorf("debug = %v, want %v", cfg.debug, tt.debug)
			}
		})
	}
}

// TestParseFlagsSpellings pins single-dash long flags, which is how the
// LaunchAgent plist and every README example invoke vpn-kinit. A move to
// a GNU-style parser (pflag) would read "-interface" as a cluster of
// short flags and break all of them.
func TestParseFlagsSpellings(t *testing.T) {
	for _, args := range [][]string{
		{"-interface", "utun7"},
		{"--interface", "utun7"},
		{"-interface=utun7"},
		{"--interface=utun7"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cfg, out, err := parse(t, args...)
			if err != nil {
				t.Fatalf("parseFlags(%q) error = %v, output %q", args, err, out)
			}
			if cfg.iface != "utun7" {
				t.Errorf("iface = %q, want utun7", cfg.iface)
			}
		})
	}
}

func TestParseFlagsInvalid(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"negative refresh", []string{"-refresh", "-1s"}},
		{"negative cooldown", []string{"-cooldown", "-1s"}},
		{"unknown flag", []string{"-nope"}},
		{"unparseable duration", []string{"-refresh", "soon"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, out, err := parse(t, tt.args...)
			if err == nil {
				t.Fatalf("parseFlags(%q) succeeded, want an error", tt.args)
			}
			if cfg != nil {
				t.Errorf("config = %+v, want nil on error", cfg)
			}
			// The caller only exits on the error, so the diagnostic has
			// to reach the user from here.
			if !strings.Contains(out, "Usage:") {
				t.Errorf("output %q does not include usage", out)
			}
		})
	}
}

func TestParseFlagsVersion(t *testing.T) {
	cfg, _, err := parse(t, "-version")
	if !errors.Is(err, errVersion) {
		t.Fatalf("parseFlags(-version) error = %v, want errVersion", err)
	}
	if cfg != nil {
		t.Errorf("config = %+v, want nil", cfg)
	}
}

func TestParseFlagsHelp(t *testing.T) {
	cfg, out, err := parse(t, "-h")
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags(-h) error = %v, want flag.ErrHelp", err)
	}
	if cfg != nil {
		t.Errorf("config = %+v, want nil", cfg)
	}
	// The passthrough is the one part of the interface the flag list
	// cannot describe, so usage has to spell it out.
	for _, want := range []string{"Usage:", "-interface", "-- -kt"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage does not mention %q:\n%s", want, out)
		}
	}
}

func TestParseKrb5Conf(t *testing.T) {
	tests := []struct {
		name      string
		conf      string
		wantRealm string
		wantKDCs  []string
	}{
		{
			name: "realm and kdcs",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = {
		kdc = kdc1.example.com
		kdc = kdc2.example.com:8888
		admin_server = kdc1.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc1.example.com", "kdc2.example.com:8888"},
		},
		{
			name: "only the default realm's kdcs",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	OTHER.COM = {
		kdc = kdc.other.com
	}
	EXAMPLE.COM = {
		kdc = kdc.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			name: "comments are stripped",
			conf: `# a comment
[libdefaults]
	default_realm = EXAMPLE.COM ; trailing comment

[realms]
	EXAMPLE.COM = {
		# kdc = commented.example.com
		kdc = kdc.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			name: "no default_realm",
			conf: `[realms]
	EXAMPLE.COM = {
		kdc = kdc.example.com
	}
`,
		},
		{
			name: "realm without a kdc entry falls through to DNS SRV",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM
`,
			wantRealm: "EXAMPLE.COM",
		},
		{
			// A closing brace sharing the last entry's line must not end
			// up inside the value: "kdc.example.com }" would be probed
			// as a hostname, failing forever.
			name: "a closing brace after the last entry",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = {
		kdc = kdc.example.com }
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			name: "a realm block on one line",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = { kdc = kdc.example.com }
	OTHER.COM = { kdc = kdc.other.com }
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			name: "section names are case-insensitive",
			conf: `[LibDefaults]
	Default_Realm = EXAMPLE.COM

[Realms]
	EXAMPLE.COM = {
		KDC = kdc.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			// Realm names are case-sensitive in Kerberos, so a block
			// whose name differs in case is a different realm.
			name: "a realm block in the wrong case is not the default realm",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	example.com = {
		kdc = kdc.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
		},
		{
			name: "an unclosed realm block still yields its kdcs",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = {
		kdc = kdc.example.com
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			name: "the last default_realm wins",
			conf: `[libdefaults]
	default_realm = FIRST.COM
	default_realm = SECOND.COM

[realms]
	FIRST.COM = {
		kdc = kdc.first.com
	}
	SECOND.COM = {
		kdc = kdc.second.com
	}
`,
			wantRealm: "SECOND.COM",
			wantKDCs:  []string{"kdc.second.com"},
		},
		{
			// Only one level of nesting is understood, so a sub-block's
			// closing brace ends the realm early and any kdc after it is
			// missed. Harmless in practice -- only the first kdc is ever
			// probed, and it precedes the sub-block in any realistic
			// config -- but pinned here so the limitation is visible.
			name: "a nested sub-block ends the realm early",
			conf: `[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = {
		kdc = kdc.example.com
		v4_instance_convert = {
			mail = example.com
		}
		kdc = missed.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			// Not following includes is a documented limitation; the
			// directive must at least not confuse the parser.
			name: "includedir is ignored, not followed",
			conf: `includedir /etc/krb5.conf.d/

[libdefaults]
	default_realm = EXAMPLE.COM

[realms]
	EXAMPLE.COM = {
		kdc = kdc.example.com
	}
`,
			wantRealm: "EXAMPLE.COM",
			wantKDCs:  []string{"kdc.example.com"},
		},
		{
			name: "empty file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "krb5.conf")
			if err := os.WriteFile(path, []byte(tt.conf), 0o600); err != nil {
				t.Fatal(err)
			}
			realm, kdcs := parseKrb5Conf(path)
			if realm != tt.wantRealm {
				t.Errorf("realm = %q, want %q", realm, tt.wantRealm)
			}
			if !slices.Equal(kdcs, tt.wantKDCs) {
				t.Errorf("kdcs = %q, want %q", kdcs, tt.wantKDCs)
			}
		})
	}
}

// TestParseKrb5ConfMissing covers the common case of no krb5.conf at all:
// discovery falls back to DNS SRV, and failing that runs kinit unguarded.
func TestParseKrb5ConfMissing(t *testing.T) {
	realm, kdcs := parseKrb5Conf(filepath.Join(t.TempDir(), "absent.conf"))
	if realm != "" || kdcs != nil {
		t.Errorf("parseKrb5Conf(missing) = %q, %q, want empty", realm, kdcs)
	}
}
