package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"vaultfs/internal/config"
	"vaultfs/internal/storage"
)

var rootCmd = &cobra.Command{
	Use:   "vaultfs",
	Short: "Encrypted file vault system",
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
