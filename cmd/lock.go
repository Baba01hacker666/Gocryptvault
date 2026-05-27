package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault (clear memory keys)",
	RunE: func(cmd *cobra.Command, args []string) error {
		v := getVault()
		v.Lock()
		fmt.Println("Vault locked. Keys wiped from memory.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
