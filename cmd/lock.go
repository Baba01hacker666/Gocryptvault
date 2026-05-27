package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"vaultfs/internal/daemon"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault (clear memory keys)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := daemon.ConnectRPC()
		if err != nil {
			fmt.Println("Daemon is not running. Vault is already locked.")
			return nil
		}
		defer client.Close()

		var reply bool
		err = client.Call("VaultDaemon.Lock", &struct{}{}, &reply)
		if err != nil {
			return fmt.Errorf("failed to lock vault via daemon: %w", err)
		}

		fmt.Println("Vault locked.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
