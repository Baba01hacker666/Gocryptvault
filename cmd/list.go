package cmd

import (
	"fmt"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
	"github.com/spf13/cobra"
)

var (
	distList       bool
	distListCoord  string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List files in the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		var files []*types.FileRecord
		var err error

		if distList {
			tlsConfig, err := security.LoadTLSConfig(distCA, distCert, distKey, false)
			if err != nil {
				return fmt.Errorf("failed to load TLS config: %w", err)
			}

			c, err := client.NewClient()
			if err != nil {
				return fmt.Errorf("failed to connect to daemon: %w", err)
			}
			defer c.Close()

			files, err = c.ListFilesDistributed(distListCoord, tlsConfig, distHidden, distHiddenPass)
			if err != nil {
				return fmt.Errorf("distributed list failed: %w", err)
			}
		} else {
			// Try RPC first for better performance (daemon-side cache)
			files, err = daemon.ListFilesRPC()
			if err != nil {
				// Fallback to local if daemon is not running or other error
				v := getVault()
				files, err = v.ListFiles()
				if err != nil {
					return fmt.Errorf("failed to list files: %w", err)
				}
			}
		}

		fmt.Printf("%-36s | %-20s | %-10s | %-20s\n", "ID", "Filename", "Size", "Created")
		fmt.Println("---------------------------------------------------------------------------------------------------")
		for _, f := range files {
			created := time.Unix(f.Created, 0).Format(time.RFC3339)
			fmt.Printf("%-36s | %-20s | %-10d | %-20s\n", f.ID, f.Filename, f.Size, created)
		}

		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&distList, "distributed", false, "Use distributed mode")
	listCmd.Flags().StringVar(&distListCoord, "coordinator", "127.0.0.1:50051", "Coordinator address")
	// Re-use certificates from add command
	listCmd.Flags().StringVar(&distCA, "ca", "ca.crt", "CA certificate for distributed mode")
	listCmd.Flags().StringVar(&distCert, "cert", "client.crt", "Client certificate for distributed mode")
	listCmd.Flags().StringVar(&distKey, "key", "client.key", "Client key for distributed mode")
	listCmd.Flags().BoolVar(&distHidden, "hidden", false, "Use hidden vault")
	listCmd.Flags().StringVar(&distHiddenPass, "hidden-password", "", "Password for hidden vault")

	rootCmd.AddCommand(listCmd)
}
