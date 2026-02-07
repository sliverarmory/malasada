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

func TestPatchSOToCallExport_LinuxAMD64(t *testing.T) {
	so := buildHelloSO(t, ArchLinuxAMD64)
	arch, patched, err := patchSOToCallExport(so, "Hello")
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if arch != ArchLinuxAMD64 {
		t.Fatalf("arch mismatch: %v", arch)
	}

	h, err := parseELF64Header(patched)
	if err != nil {
		t.Fatalf("parse patched header: %v", err)
	}
	if h.entry == 0 {
		t.Fatalf("expected non-zero e_entry")
	}

	phdrs, err := parseELF64Phdrs(patched, h)
	if err != nil {
		t.Fatalf("parse phdrs: %v", err)
	}
	var found bool
	for _, ph := range phdrs {
		if ph.typ != ptLoad {
			continue
		}
		if ph.vaddr != h.entry {
			continue
		}
		if ph.flags&(pfR|pfX) != (pfR | pfX) {
			t.Fatalf("stub segment missing R|X flags: 0x%x", ph.flags)
		}
		if ph.off+ph.filesz > uint64(len(patched)) {
			t.Fatalf("stub segment outside file")
		}
		stub := patched[ph.off : ph.off+ph.filesz]
		if !bytes.HasPrefix(stub, []byte{0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B}) { // call; pop rbx
			t.Fatalf("amd64 stub prefix mismatch: %x", stub[:8])
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find stub PT_LOAD segment at entry")
	}
}

func TestPatchSOToCallExport_LinuxARM64(t *testing.T) {
	so := buildHelloSO(t, ArchLinuxARM64)
	arch, patched, err := patchSOToCallExport(so, "Hello")
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if arch != ArchLinuxARM64 {
		t.Fatalf("arch mismatch: %v", arch)
	}

	h, err := parseELF64Header(patched)
	if err != nil {
		t.Fatalf("parse patched header: %v", err)
	}
	if h.entry == 0 {
		t.Fatalf("expected non-zero e_entry")
	}

	phdrs, err := parseELF64Phdrs(patched, h)
	if err != nil {
		t.Fatalf("parse phdrs: %v", err)
	}
	var found bool
	for _, ph := range phdrs {
		if ph.typ != ptLoad {
			continue
		}
		if ph.vaddr != h.entry {
			continue
		}
		if ph.flags&(pfR|pfX) != (pfR | pfX) {
			t.Fatalf("stub segment missing R|X flags: 0x%x", ph.flags)
		}
		if ph.off+ph.filesz > uint64(len(patched)) {
			t.Fatalf("stub segment outside file")
		}
		stub := patched[ph.off : ph.off+ph.filesz]
		// First instruction is `adr x19, .` => word 0x10000013 LE.
		if len(stub) < 4 || !bytes.Equal(stub[:4], []byte{0x13, 0x00, 0x00, 0x10}) {
			t.Fatalf("arm64 stub prefix mismatch: %x", stub[:8])
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find stub PT_LOAD segment at entry")
	}
}

func TestStage0HeaderAtEnd(t *testing.T) {
	t.Setenv("ZIG_GLOBAL_CACHE_DIR", filepath.Join(t.TempDir(), "zig-cache"))
	t.Setenv("ZIG_LOCAL_CACHE_DIR", filepath.Join(t.TempDir(), "zig-cache-local"))

	for _, arch := range []Arch{ArchLinuxAMD64, ArchLinuxARM64} {
		stage0, err := buildStage0(arch)
		if err != nil {
			t.Fatalf("buildStage0(%v): %v", arch, err)
		}
		if bytes.LastIndex(stage0, msdaMagic) != len(stage0)-(8+4+4+8) {
			t.Fatalf("stage0(%v): msda header not at end", arch)
		}
		// Should be patchable without error.
		if err := patchStage0PayloadLen(stage0, 123); err != nil {
			t.Fatalf("patchStage0PayloadLen(%v): %v", arch, err)
		}
	}
}

func buildHelloSO(t *testing.T, arch Arch) []byte {
	t.Helper()
	tmp := t.TempDir()

	t.Setenv("GOCACHE", filepath.Join(tmp, "go-cache"))
	t.Setenv("GOMODCACHE", filepath.Join(tmp, "go-modcache"))
	t.Setenv("ZIG_GLOBAL_CACHE_DIR", filepath.Join(tmp, "zig-cache"))
	t.Setenv("ZIG_LOCAL_CACHE_DIR", filepath.Join(tmp, "zig-cache-local"))

	goos := "linux"
	goarch := ""
	zigTarget := ""
	machineWant := elf.EM_NONE
	switch arch {
	case ArchLinuxAMD64:
		goarch = "amd64"
		zigTarget = "x86_64-linux-gnu"
		machineWant = elf.EM_X86_64
	case ArchLinuxARM64:
		goarch = "arm64"
		zigTarget = "aarch64-linux-gnu"
		machineWant = elf.EM_AARCH64
	default:
		t.Fatalf("unsupported arch %v", arch)
	}

	soPath := filepath.Join(tmp, "hello.so")

	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", soPath, "./testdata/hello")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"GOOS="+goos,
		"GOARCH="+goarch,
	)
	// On linux, prefer native builds (no Zig dependency) for the current arch.
	// For cross-arch builds, fall back to Zig if available; otherwise skip.
	if !(runtime.GOOS == "linux" && runtime.GOARCH == goarch) {
		if _, err := exec.LookPath("zig"); err != nil {
			t.Skipf("zig not found (needed to cross-compile %s from %s/%s): %v", arch, runtime.GOOS, runtime.GOARCH, err)
		}
		cmd.Env = append(cmd.Env, "CC=zig cc -target "+zigTarget)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build hello.so (%v): %v", arch, err)
	}

	so, err := os.ReadFile(soPath)
	if err != nil {
		t.Fatalf("read hello.so: %v", err)
	}

	ef, err := elf.NewFile(bytes.NewReader(so))
	if err != nil {
		t.Fatalf("elf parse: %v", err)
	}
	if ef.Machine != machineWant {
		t.Fatalf("machine mismatch: got %v want %v", ef.Machine, machineWant)
	}
	return so
}
