# Makefile for git-remote-cloak: build targets and the verification gates
# used in place of CI. All test targets force TMPDIR under ~/tmp per the
# operator's temp-file convention; integration TestMain enforces it.

BIN := bin
TMPDIR := $(HOME)/tmp
export TMPDIR

PREFIX ?= $(HOME)/bin
# Default to the latest release tag reachable from the current checkout
# (e.g. v0.1.5) -- only the clean version string, no commit/sha/-dirty suffix.
# Override explicitly with `make install VERSION=v0.1.5`. Falls back to
# "unknown" only when no tag is reachable (e.g. outside a git checkout).
# Never defaults to "dev".
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/b4ryon/git-remote-cloak/internal/version.Version=$(VERSION)
DIST := dist

.PHONY: build release install check-go test test-integration test-race test-darwin test-e2e vet vuln check fmt sign clean

# Code-signing identity for stable Keychain item ACLs. Default is ad-hoc
# (identity changes per build, so the ACL re-prompts). Set CLOAK_SIGN_ID to a
# stable self-signed code-signing certificate for prompt-free rebuilds, e.g.
#   make sign CLOAK_SIGN_ID=cloak-codesign
CLOAK_SIGN_ID ?= -

build:
	mkdir -p $(BIN) $(TMPDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/git-remote-cloak ./cmd/git-remote-cloak
	ln -sf git-remote-cloak $(BIN)/git-cloak

# Release binaries: signed darwin/arm64 (cgo Keychain) and a static
# Linux/amd64 (pure Go, file keystore). Run with VERSION=v0.1.0.
release:
	mkdir -p $(DIST)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/git-remote-cloak-darwin-arm64 ./cmd/git-remote-cloak
	codesign --force --sign "$(CLOAK_SIGN_ID)" $(DIST)/git-remote-cloak-darwin-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/git-remote-cloak-linux-amd64 ./cmd/git-remote-cloak

# Fail fast with a one-line, OS-specific install hint when the Go toolchain is
# missing, instead of letting `go build` dump a raw "go: command not found".
check-go:
	@command -v go >/dev/null 2>&1 || { \
		echo "Error: Go toolchain not found ('go' is not on PATH)."; \
		case "$$(uname -s)" in \
			Darwin) echo "Install Go: brew install go   (or download from https://go.dev/dl/)";; \
			Linux)  echo "Install Go: sudo apt install golang-go   (Debian/Ubuntu), your distro's package, or https://go.dev/dl/";; \
			*)      echo "Install Go from https://go.dev/dl/";; \
		esac; \
		exit 1; \
	}

install: check-go build
	install -d $(PREFIX)
	install $(BIN)/git-remote-cloak $(PREFIX)/git-remote-cloak
	ln -sf git-remote-cloak $(PREFIX)/git-cloak

# -count=1 disables the test cache: go test does NOT track the rebuilt helper
# binary, so a cached integration result can pass against a stale binary.
test:
	mkdir -p $(TMPDIR)
	go test -count=1 ./internal/...

test-integration: build
	mkdir -p $(TMPDIR)
	go test -count=1 ./test/integration/... ./test/security/...

# Race detector over the in-process suites (catches data races in any
# goroutines the helper/engine spawn). Subprocess behavior is covered by the
# integration suite above.
test-race: build
	mkdir -p $(TMPDIR)
	go test -race -count=1 ./internal/... ./test/integration/... ./test/security/...

test-darwin:
	mkdir -p $(TMPDIR)
	go test -count=1 -tags darwinkeystore ./internal/keystore/...

test-e2e: build
	mkdir -p $(TMPDIR)
	go test -count=1 -tags e2e ./test/e2e/...

sign: build
	codesign --force --sign "$(CLOAK_SIGN_ID)" $(BIN)/git-remote-cloak

vet:
	go vet ./...

# Vulnerability scan of dependencies and reachable stdlib. Install once with:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
# Requires network access to the Go vulnerability database (vuln.go.dev).
vuln:
	govulncheck ./...

# Aggregate gate: formatting, vet, vulnerabilities, and every test suite.
check: vet vuln test test-integration test-darwin

fmt:
	gofmt -l -w cmd internal test

clean:
	rm -rf $(BIN) dist
