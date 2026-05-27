package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export [file_id] [output_dir]",
	Short: "Export a file from the vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fileID := args[0]
		outDir := args[1]

		if info, err := os.Stat(outDir); err != nil || !info.IsDir() {
			return fmt.Errorf("output directory does not exist or is not a directory")
		}

		v := getVault()
		if err := v.ExportFile(fileID, outDir); err != nil {
			return fmt.Errorf("failed to export file: %w", err)
		}

		fmt.Println("File exported successfully to", outDir)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
}
