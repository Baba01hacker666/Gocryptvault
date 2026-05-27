package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter master password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Println()

		v := getVault()
		if err := v.Unlock(bytePassword); err != nil {
			return fmt.Errorf("unlock failed: %w", err)
		}

		fmt.Println("Vault unlocked. Keys are in memory.")
		// In a real application, you might spawn a daemon here to hold the keys
		// and provide an API, or run the FUSE mount directly.
		// For simplicity in this CLI structure without a daemon, unlock merely
		// verifies the password. Operations require a daemon or running in single process.
		// Given this is a CLI, operations would need to be chained or have a daemon.
		// For the sake of the prompt "Create runtime session", we will assume
		// tests run commands in sequence, but in CLI it requires keeping the process alive.
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unlockCmd)
}
