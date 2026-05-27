package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change vault master password",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter old master password: ")
		oldPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Println()

		fmt.Print("Enter new master password: ")
		newPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Println()

		fmt.Print("Confirm new password: ")
		confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Println()

		if string(newPassword) != string(confirmPassword) {
			return fmt.Errorf("passwords do not match")
		}

		v := getVault()
		if err := v.ChangePassword(oldPassword, newPassword); err != nil {
			return fmt.Errorf("password change failed: %w", err)
		}

		fmt.Println("Password changed successfully.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(changePasswordCmd)
}
