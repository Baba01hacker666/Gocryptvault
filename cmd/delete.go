package cmd

import (
	"fmt"

	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/spf13/cobra"
)

var (
	distDelete      bool
	distDeleteCoord string
)

var deleteCmd = &cobra.Command{
	Use:   "delete [file_id]",
	Short: "Delete a file from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fileID := args[0]

		if distDelete {
			tlsConfig, err := security.LoadTLSConfig(distCA, distCert, distKey, false)
			if err != nil {
				return fmt.Errorf("failed to load TLS config: %w", err)
			}

			c, err := client.NewClient()
			if err != nil {
				return fmt.Errorf("failed to connect to daemon: %w", err)
			}
			defer c.Close()

			if err := c.DeleteFileDistributed(fileID, distDeleteCoord, tlsConfig, distHidden, distHiddenPass); err != nil {
				return fmt.Errorf("distributed delete failed: %w", err)
			}
		} else {
			v := getVault()
			if err := v.DeleteFile(fileID); err != nil {
				return fmt.Errorf("failed to delete file: %w", err)
			}
		}

		fmt.Println("File deleted successfully.")
		return nil
	},
}

func init() {
	deleteCmd.Flags().BoolVar(&distDelete, "distributed", false, "Use distributed mode")
	deleteCmd.Flags().StringVar(&distDeleteCoord, "coordinator", "127.0.0.1:50051", "Coordinator address")
	deleteCmd.Flags().StringVar(&distCA, "ca", "ca.crt", "CA certificate for distributed mode")
	deleteCmd.Flags().StringVar(&distCert, "cert", "client.crt", "Client certificate for distributed mode")
	deleteCmd.Flags().StringVar(&distKey, "key", "client.key", "Client key for distributed mode")
	deleteCmd.Flags().BoolVar(&distHidden, "hidden", false, "Use hidden vault")
	deleteCmd.Flags().StringVar(&distHiddenPass, "hidden-password", "", "Password for hidden vault")

	rootCmd.AddCommand(deleteCmd)
}
