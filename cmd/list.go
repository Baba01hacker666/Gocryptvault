package cmd

import (
	"fmt"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List files in the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Try RPC first for better performance (daemon-side cache)
		files, err := daemon.ListFilesRPC()
		if err != nil {
			// Fallback to local if daemon is not running or other error
			v := getVault()
			files, err = v.ListFiles()
			if err != nil {
				return fmt.Errorf("failed to list files: %w", err)
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
	rootCmd.AddCommand(listCmd)
}
