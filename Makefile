GO ?= go

# Default to the current host Go target (override as needed):
#   make GOOS=linux GOARCH=amd64
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

# Go's default build cache lives outside the workspace on macOS. Keep it
# workspace-local so builds work in sandboxed environments.
GOCACHE ?= $(CURDIR)/.cache/go-build
ZIG_GLOBAL_CACHE_DIR ?= $(CURDIR)/.cache/zig
ZIG_LOCAL_CACHE_DIR ?= $(CURDIR)/.cache/zig-local

# The CLI does not use cgo; forcing this makes cross-compiles more reliable.
CGO_ENABLED ?= 0

EXE :=
ifeq ($(GOOS),windows)
EXE := .exe
endif

OUT ?= malasada$(EXE)

STAGE0_BINS := internal/stage0/stage0_linux_amd64.bin internal/stage0/stage0_linux_arm64.bin

.PHONY: all build test clean stage0 check-stage0

all: build

# Build the CLI for the current GOOS/GOARCH (or overridden values).
build: check-stage0
	GOCACHE=$(GOCACHE) GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
		$(GO) build -trimpath -o $(OUT) ./cli

test: check-stage0
	GOCACHE=$(GOCACHE) $(GO) test ./...

clean:
	rm -f $(OUT)

# Force regeneration of the embedded stage0 blobs.
stage0:
	GOCACHE=$(GOCACHE) ZIG_GLOBAL_CACHE_DIR=$(ZIG_GLOBAL_CACHE_DIR) ZIG_LOCAL_CACHE_DIR=$(ZIG_LOCAL_CACHE_DIR) \
		$(GO) generate ./...

check-stage0:
	@for f in $(STAGE0_BINS); do \
		if [ ! -f "$$f" ]; then \
			echo "Missing $$f"; \
			echo "Run: make stage0"; \
			exit 1; \
		fi; \
	done
