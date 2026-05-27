package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"vaultfs/internal/fuse"
)

var mountCmd = &cobra.Command{
	Use:   "mount [mountpoint]",
	Short: "Mount the vault via FUSE",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mountpoint := args[0]
		if info, err := os.Stat(mountpoint); err != nil || !info.IsDir() {
			return fmt.Errorf("mountpoint does not exist or is not a directory")
		}

		v := getVault()
		// Assume unlocked previously via daemon or CLI context
		if err := fuse.Mount(mountpoint, v); err != nil {
			return fmt.Errorf("failed to mount vault: %w", err)
		}

		fmt.Println("Vault mounted successfully at", mountpoint)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mountCmd)
}
