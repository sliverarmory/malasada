ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm AS test

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    libc6-dev \
  && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1

WORKDIR /src
COPY . .

RUN go build -o /usr/local/bin/malasada ./cli

RUN go build -buildmode=c-shared -o /tmp/hello.so ./testdata/hello

RUN /usr/local/bin/malasada --call-export Hello -o /tmp/hello.bin /tmp/hello.so

RUN gcc -O2 -o /tmp/runner ./testdata/runner/runner.c

# The payload replaces the process image (exec-like), so runner does not return.
RUN /tmp/runner /tmp/hello.bin | grep -q "hello from go"

# SUBSTANTIAL_INDUSTRY is linux/amd64-only and does not return once StartW is
# called. Treat "timed out" as success (we only want to ensure it doesn't crash
# immediately).
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
      /usr/local/bin/malasada -o /tmp/substantial.bin ./testdata/SUBSTANTIAL_INDUSTRY.so && \
      timeout -k 1s 1s /tmp/runner /tmp/substantial.bin; \
      rc=$?; \
      if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then exit 0; fi; \
      exit "$rc"; \
    fi
