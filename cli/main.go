package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sliverarmory/malasada"
	"github.com/spf13/cobra"
)

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		outPath    string
		exportName string
		compress   bool
	)

	cmd := &cobra.Command{
		Use:   "malasada [flags] <input.so>",
		Short: "Convert a Linux ELF shared object (.so) into an executable PIC .bin blob",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: %s [flags] <input.so>", cmd.CommandPath())
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			soPath := args[0]
			if outPath == "" {
				outPath = soPath + ".bin"
			}

			bin, err := malasada.ConvertSharedObject(soPath, exportName, compress)
			if err != nil {
				return err
			}

			dir := filepath.Dir(outPath)
			if dir != "." {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return fmt.Errorf("mkdir: %w", err)
				}
			}
			if err := os.WriteFile(outPath, bin, 0o755); err != nil {
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outPath, "o", "o", "", "Output .bin path (default: <input>.bin)")
	cmd.Flags().StringVar(&exportName, "call-export", malasada.DefaultCallExport, "Exported function name to call after the .so is loaded")
	cmd.Flags().BoolVar(&compress, "compress", false, "Compress the embedded .so payload with aPLib (default: false)")
	cmd.Flags().BoolVar(&compress, "compression", false, "Alias for --compress")

	return cmd
}
