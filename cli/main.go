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
		compress   bool
	)

	flag.StringVar(&outPath, "o", "", "Output .bin path (default: <input>.bin)")
	flag.StringVar(&exportName, "call-export", malasada.DefaultCallExport, "Exported function name to call after the .so is loaded")
	flag.BoolVar(&compress, "compression", false, "Compress the embedded .so payload with aPLib (default: false)")
	flag.Parse()

	if flag.NArg() != 1 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: malasada [flags] <input.so>\n")
		os.Exit(1)
	}
	soPath := flag.Arg(0)
	if outPath == "" {
		outPath = soPath + ".bin"
	}

	bin, err := malasada.ConvertSharedObject(soPath, exportName, compress)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	dir := filepath.Dir(outPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			os.Exit(1)
		}
	}
	if err := os.WriteFile(outPath, bin, 0o755); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
		os.Exit(1)
	}
}
