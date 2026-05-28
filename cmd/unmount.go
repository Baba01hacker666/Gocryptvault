package cmd

import (
	"fmt"

	"github.com/Baba01hacker666/Gocryptvault/internal/fuse"
	"github.com/spf13/cobra"
)

var unmountCmd = &cobra.Command{
	Use:   "unmount [mountpoint]",
	Short: "Unmount the vault FUSE filesystem",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mountpoint := args[0]
		if err := fuse.Unmount(mountpoint); err != nil {
			return fmt.Errorf("failed to unmount vault: %w", err)
		}

		fmt.Println("Vault unmounted successfully.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unmountCmd)
}
