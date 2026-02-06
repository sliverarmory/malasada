GO ?= go

# Default to the current host Go target (override as needed):
#   make GOOS=linux GOARCH=amd64
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

# The CLI does not use cgo; forcing this makes cross-compiles more reliable.
CGO_ENABLED ?= 0

EXE :=
ifeq ($(GOOS),windows)
EXE := .exe
endif

OUT ?= malasada$(EXE)

STAGE0_BINS := internal/stage0/stage0_linux_amd64.bin internal/stage0/stage0_linux_arm64.bin

.PHONY: all build test clean stage0

all: build

# Build the CLI for the current GOOS/GOARCH (or overridden values).
build: $(STAGE0_BINS)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
		$(GO) build -trimpath -o $(OUT) ./cli

test: $(STAGE0_BINS)
	$(GO) test ./...

clean:
	rm -f $(OUT)

# Force regeneration of the embedded stage0 blobs.
stage0:
	$(GO) generate ./...

# Ensure the embedded stage0 blobs exist and are up to date.
$(STAGE0_BINS): internal/stage0/stage0.c internal/stage0/linker.ld internal/stage0/genstage0/main.go
	$(GO) generate ./...
