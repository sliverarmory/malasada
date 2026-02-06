ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm AS test

ARG TARGETARCH
ARG ZIG_VERSION=0.15.2

RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    curl \\
    xz-utils \\
  && rm -rf /var/lib/apt/lists/*

# Install zig (used both as a C compiler and for stage0 builds).
RUN set -eux; \\
  case "${TARGETARCH}" in \\
    amd64) ZIG_ARCH="x86_64" ;; \\
    arm64) ZIG_ARCH="aarch64" ;; \\
    *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \\
  esac; \\
  curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz" | tar -xJ -C /opt; \\
  ln -s "/opt/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}/zig" /usr/local/bin/zig

ENV CGO_ENABLED=1
ENV CC="zig cc"

WORKDIR /src
COPY . .

RUN go build -o /usr/local/bin/malasada ./cli

RUN go build -buildmode=c-shared -o /tmp/hello.so ./testdata/hello

RUN /usr/local/bin/malasada --call-export Hello -o /tmp/hello.bin /tmp/hello.so

RUN zig cc -O2 -o /tmp/runner ./testdata/runner/runner.c

# The payload replaces the process image (exec-like), so runner does not return.
RUN /tmp/runner /tmp/hello.bin | grep -q "hello from go"

