package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var asyncAdd bool

var addCmd = &cobra.Command{
	Use:   "add [file]",
	Short: "Add a file to the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		if _, err := os.Stat(filePath); err != nil {
			return err
		}

		v := getVault()
		// Assume unlocked previously in context of a test or daemon
		if asyncAdd {
			fmt.Println("Adding file asynchronously...")
			errChan := v.AddFileAsync(filePath)
			err := <-errChan
			if err != nil {
				return fmt.Errorf("failed to add file asynchronously: %w", err)
			}
			fmt.Println("File added successfully.")
		} else {
			if err := v.AddFile(filePath); err != nil {
				return fmt.Errorf("failed to add file: %w", err)
			}
			fmt.Println("File added successfully.")
		}

		return nil
	},
}

func init() {
	addCmd.Flags().BoolVar(&asyncAdd, "async", false, "Add file asynchronously")
	rootCmd.AddCommand(addCmd)
}
