package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter new master password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Println()

		fmt.Print("Confirm password: ")
		confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Println()

		if string(bytePassword) != string(confirmPassword) {
			return fmt.Errorf("passwords do not match")
		}

		v := getVault()
		if err := v.Init(bytePassword); err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}

		fmt.Println("Vault initialized successfully at", v.BaseDir)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
