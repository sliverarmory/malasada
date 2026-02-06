package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sliverarmory/malasada"
)

func main() {
	var (
		outPath    string
		exportName string
		zigPath    string
	)

	flag.StringVar(&outPath, "o", "", "Output .bin path (default: <input>.bin)")
	flag.StringVar(&exportName, "call-export", "", "Exported function name to call after the .so is loaded")
	flag.StringVar(&zigPath, "zig", "", "Optional: rebuild stage0 with zig instead of using embedded prebuilt stage0 (value: path to zig)")
	flag.Parse()

	if exportName == "" {
		fatalf("missing required flag: --call-export")
	}

	if flag.NArg() != 1 {
		fatalf("usage: malasada [flags] <input.so>")
	}
	soPath := flag.Arg(0)
	if outPath == "" {
		outPath = soPath + ".bin"
	}

	bin, err := malasada.ConvertSharedObject(soPath, exportName, malasada.BuildOptions{
		ZigPath: zigPath,
	})
	if err != nil {
		fatalf("%v", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil && filepath.Dir(outPath) != "." {
		fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(outPath, bin, 0o755); err != nil {
		fatalf("write %s: %v", outPath, err)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
