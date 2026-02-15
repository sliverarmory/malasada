//go:build linux

package malasada

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConvertSharedObject_CompressE2E(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" && runtime.GOARCH != "386" {
		t.Skipf("unsupported GOARCH %q", runtime.GOARCH)
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("missing gcc: %v", err)
	}

	tmp := t.TempDir()
	t.Setenv("GOCACHE", filepath.Join(tmp, "go-cache"))
	t.Setenv("GOMODCACHE", filepath.Join(tmp, "go-modcache"))

	soPath := filepath.Join(tmp, "hello.so")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", soPath, "./testdata/hello")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build hello.so: %v", err)
	}

	rawBin, err := ConvertSharedObject(soPath, "Hello", false)
	if err != nil {
		t.Fatalf("ConvertSharedObject(compress=false): %v", err)
	}
	compBin, err := ConvertSharedObject(soPath, "Hello", true)
	if err != nil {
		t.Fatalf("ConvertSharedObject(compress=true): %v", err)
	}

	// Sanity: compressed payload should start with the AP32 safe header.
	so, err := os.ReadFile(soPath)
	if err != nil {
		t.Fatalf("read hello.so: %v", err)
	}
	ef, err := elf.NewFile(bytes.NewReader(so))
	if err != nil {
		t.Fatalf("elf parse: %v", err)
	}
	arch, err := archFromELFMachine(ef.Machine)
	if err != nil {
		t.Fatalf("archFromELFMachine: %v", err)
	}
	stage0, err := buildStage0(arch)
	if err != nil {
		t.Fatalf("buildStage0: %v", err)
	}
	if len(compBin) <= len(stage0) || !bytes.HasPrefix(compBin[len(stage0):], []byte("AP32")) {
		t.Fatalf("expected compressed payload to start with AP32 header")
	}

	rawPath := filepath.Join(tmp, "hello.raw.bin")
	if err := os.WriteFile(rawPath, rawBin, 0o644); err != nil {
		t.Fatalf("write raw bin: %v", err)
	}
	compPath := filepath.Join(tmp, "hello.comp.bin")
	if err := os.WriteFile(compPath, compBin, 0o644); err != nil {
		t.Fatalf("write compressed bin: %v", err)
	}

	runnerPath := filepath.Join(tmp, "runner")
	cmd = exec.Command("gcc", "-O2", "-o", runnerPath, "./testdata/runner/runner.c")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gcc runner: %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "uncompressed", path: rawPath},
		{name: "compressed", path: compPath},
	} {
		out, err := exec.Command(runnerPath, tc.path).CombinedOutput()
		if err != nil {
			t.Fatalf("%s runner failed: %v\n%s", tc.name, err, string(out))
		}
		if !bytes.Contains(out, []byte("hello from go")) {
			t.Fatalf("%s: missing output substring; got:\n%s", tc.name, string(out))
		}
	}
}
