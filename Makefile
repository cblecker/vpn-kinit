BINARY  := vpn-kinit
LABEL   := com.cblecker.vpn-kinit
PREFIX  ?= $(HOME)/.local
BINDIR  := $(PREFIX)/bin
PLIST_IN  := LaunchAgents/$(LABEL).plist.in
PLIST_OUT := $(HOME)/Library/LaunchAgents/$(LABEL).plist
UID     := $(shell id -u)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

export GOOS        := darwin
export CGO_ENABLED := 0

GOLANGCI_LINT ?= golangci-lint

.PHONY: all build vet fmt lint check install uninstall clean

all: build

build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) .

vet:
	go vet ./...

# gofmt is also enforced by the gofmt formatter in .golangci.yml; this target
# repeats it so `make check` catches unformatted code with no extra tooling.
fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

# CI runs golangci-lint via golangci-lint-action, so a missing local binary is
# a skip rather than a failure.
lint:
	@command -v $(GOLANGCI_LINT) >/dev/null || \
	    { echo "$(GOLANGCI_LINT) not installed, skipping"; exit 0; }; \
	  $(GOLANGCI_LINT) config verify && $(GOLANGCI_LINT) run ./...

check: vet fmt lint

install: build
	@test "$$(uname -s)" = "Darwin" || (echo "install must run on macOS" && exit 1)
	install -d $(BINDIR) $(HOME)/Library/LaunchAgents
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	launchctl bootout gui/$(UID)/$(LABEL) 2>/dev/null || [ $$? -eq 3 ]
	sed -e 's|@BINARY@|$(BINDIR)/$(BINARY)|g' \
	    -e 's|@HOME@|$(HOME)|g' $(PLIST_IN) > $(PLIST_OUT)
	plutil -lint $(PLIST_OUT)
	launchctl bootstrap gui/$(UID) $(PLIST_OUT)

uninstall:
	@test "$$(uname -s)" = "Darwin" || (echo "uninstall must run on macOS" && exit 1)
	launchctl bootout gui/$(UID)/$(LABEL) 2>/dev/null || [ $$? -eq 3 ]
	rm -f $(PLIST_OUT) $(BINDIR)/$(BINARY)

clean:
	rm -rf bin
