package cmd

import (
	"fmt"
	"os"

	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
	"github.com/spf13/cobra"
)

var (
	distExport      bool
	distExportCoord string
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

		if distExport {
			fmt.Printf("Exporting file %s in distributed mode...\n", fileID)

			args := &types.DistExportArgs{
				FileID:     fileID,
				DestDir:    outDir,
				CoordAddr:  distExportCoord,
				CA:         distCA,
				Cert:       distCert,
				Key:        distKey,
				Hidden:     distHidden,
				HiddenPass: distHiddenPass,
			}

			if err := daemon.ExportFileDistributedRPC(args); err != nil {
				return fmt.Errorf("distributed export failed: %w", err)
			}
		} else {
			v := getVault()
			if err := v.ExportFile(fileID, outDir); err != nil {
				return fmt.Errorf("failed to export file: %w", err)
			}
		}

		fmt.Println("File exported successfully to", outDir)
		return nil
	},
}

func init() {
	exportCmd.Flags().BoolVar(&distExport, "distributed", false, "Use distributed mode")
	exportCmd.Flags().StringVar(&distExportCoord, "coordinator", "127.0.0.1:50051", "Coordinator address")
	// Re-use certificates from add command
	exportCmd.Flags().StringVar(&distCA, "ca", "ca.crt", "CA certificate for distributed mode")
	exportCmd.Flags().StringVar(&distCert, "cert", "client.crt", "Client certificate for distributed mode")
	exportCmd.Flags().StringVar(&distKey, "key", "client.key", "Client key for distributed mode")
	exportCmd.Flags().BoolVar(&distHidden, "hidden", false, "Use hidden vault")
	exportCmd.Flags().StringVar(&distHiddenPass, "hidden-password", "", "Password for hidden vault")

	rootCmd.AddCommand(exportCmd)
}
