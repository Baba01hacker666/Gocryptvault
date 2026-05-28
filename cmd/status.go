package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Baba01hacker666/Gocryptvault/internal/config"
	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status",
	RunE: func(cmd *cobra.Command, args []string) error {
		vPath := config.GetVaultPath()
		fmt.Println("Vault Path:", vPath)

		if _, err := os.Stat(filepath.Join(vPath, "config.enc")); os.IsNotExist(err) {
			fmt.Println("Status: Not initialized")
			return nil
		}

		client, err := daemon.ConnectRPC()
		if err != nil {
			fmt.Println("Status: Locked")
			return nil
		}
		defer client.Close()

		var reply daemon.StatusReply
		err = client.Call("VaultDaemon.Status", &struct{}{}, &reply)
		if err != nil {
			fmt.Println("Status: Locked (Daemon error)")
			return nil
		}

		if reply.Unlocked {
			fmt.Println("Status: Unlocked")
			fmt.Println("Auto-lock in:", reply.TimeUntilLock)
		} else {
			fmt.Println("Status: Locked")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
