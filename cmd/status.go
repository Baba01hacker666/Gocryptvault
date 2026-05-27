package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"vaultfs/internal/config"
	"vaultfs/internal/session"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status",
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultPath := config.GetVaultPath()
		configPath := filepath.Join(vaultPath, "config.enc")

		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Println("Vault is not initialized.")
			return nil
		}

		_, err := session.GetSession()
		if err != nil {
			fmt.Println("Vault is locked.")
		} else {
			fmt.Println("Vault is unlocked.")
		}

		fmt.Println("Vault directory:", vaultPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
