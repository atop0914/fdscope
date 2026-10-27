VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

MODULE  := github.com/atop0914/fdscope
CMD     := ./cmd/fdscope
BIN     := bin/fdscope

# -trimpath belongs to `go build`, NOT to LDFLAGS: putting it in LDFLAGS makes
# the linker fail with "flag provided but not defined: -trimpath".
LDFLAGS := -s -w \
	-X $(MODULE)/internal/cli.Version=$(VERSION) \
	-X $(MODULE)/internal/version.GitCommit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(DATE)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all
all: fmt vet test build

.PHONY: fmt
fmt: ## format all Go sources
	@$(shell go env GOROOT)/bin/gofmt -s -l -w $$(git ls-files '*.go')

.PHONY: fmt-check
fmt-check: ## fail when any file is unformatted
	@out=$$($(shell go env GOROOT)/bin/gofmt -s -l $$(git ls-files '*.go')); \
	if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test -count=1 ./...

.PHONY: test-race
test-race: ## full race run; needs an explicit timeout on small machines
	go test -count=1 -race -timeout 1800s ./...

.PHONY: build
build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) $(CMD)

# The cross-compilation gate. CI only runs linux/amd64, so platform-specific
# code is invisible until a release tags a multi-platform build. This target is
# the cheapest way to find out early: it compiles, and produces nothing.
#
# It ends with a darwin vet because compiling is not enough for platform-specific
# *test* files: `go build` skips them, so a darwin-only test that stopped
# compiling would stay invisible until someone ran the suite on a Mac - and the
# non-Linux refusal is exactly that kind of test. Windows is left out of the vet on
# purpose: its syscall package has no Setsid, and every fixture here starts its
# child in its own session.
.PHONY: build-check
build-check:
	@set -e; for platform in $(PLATFORMS); do \
		goos=$${platform%/*}; goarch=$${platform#*/}; \
		echo "  $$goos/$$goarch"; \
		GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 go build -trimpath -o /dev/null $(CMD); \
	done
	@$(MAKE) --no-print-directory vet-cross

.PHONY: vet-cross
vet-cross: ## type-check another platform, test files included
	@echo "  darwin/arm64 (vet, tests included)"
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: check
check: fmt-check vet build-check test

.PHONY: clean
clean:
	rm -rf bin
