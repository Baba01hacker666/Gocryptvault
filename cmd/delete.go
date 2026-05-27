package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete [file_id]",
	Short: "Delete a file from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fileID := args[0]
		v := getVault()
		if err := v.DeleteFile(fileID); err != nil {
			return fmt.Errorf("failed to delete file: %w", err)
		}

		fmt.Println("File deleted successfully.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}
