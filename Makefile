BINARY  := vpn-kinit
LABEL   := com.cblecker.vpn-kinit
PREFIX  ?= $(HOME)/.local
BINDIR  := $(PREFIX)/bin
PLIST_IN  := LaunchAgents/$(LABEL).plist.in
PLIST_OUT := $(HOME)/Library/LaunchAgents/$(LABEL).plist
UID     := $(shell id -u)

export GOOS        := darwin
export CGO_ENABLED := 0

.PHONY: all build vet check install uninstall clean

all: build

build:
	go build -trimpath -o bin/$(BINARY) .

vet:
	go vet ./...

check: vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

install: build
	@test "$$(uname -s)" = "Darwin" || (echo "install must run on macOS" && exit 1)
	install -d $(BINDIR) $(HOME)/Library/LaunchAgents
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	launchctl bootout gui/$(UID)/$(LABEL) 2>/dev/null || true
	sed -e 's|@BINARY@|$(BINDIR)/$(BINARY)|g' \
	    -e 's|@HOME@|$(HOME)|g' $(PLIST_IN) > $(PLIST_OUT)
	plutil -lint $(PLIST_OUT)
	launchctl bootstrap gui/$(UID) $(PLIST_OUT)

uninstall:
	@test "$$(uname -s)" = "Darwin" || (echo "uninstall must run on macOS" && exit 1)
	launchctl bootout gui/$(UID)/$(LABEL) 2>/dev/null || true
	rm -f $(PLIST_OUT) $(BINDIR)/$(BINARY)

clean:
	rm -rf bin
