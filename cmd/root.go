package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"vaultfs/internal/config"
	"vaultfs/internal/daemon"
	"vaultfs/internal/storage"
)

var rootCmd = &cobra.Command{
	Use:   "vaultfs",
	Short: "Encrypted file vault system",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Commands that don't need an active session
		if cmd.Name() == "init" || cmd.Name() == "unlock" || cmd.Name() == "lock" || cmd.Name() == "daemon" || cmd.Name() == "status" || cmd.Name() == "help" {
			return nil
		}

		// Ensure local session is populated by daemon for commands like add, list, export
		return daemon.EnsureLocalSession()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getVault() *storage.Vault {
	return storage.NewVault(config.GetVaultPath())
}
