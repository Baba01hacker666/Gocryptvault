package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"vaultfs/internal/daemon"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter master password: ")
		bytePassword, err := readPassword()
		if err != nil {
			return err
		}
		fmt.Println()

		client, err := daemon.ConnectRPC()
		if err != nil {
			// Daemon not running, start it
			fmt.Println("Starting daemon in background...")
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to get executable path: %w", err)
			}
			daemonCmd := exec.Command(exe, "daemon")
			if err := daemonCmd.Start(); err != nil {
				return fmt.Errorf("failed to start daemon: %w", err)
			}

			// Wait for daemon to start
			for i := 0; i < 10; i++ {
				client, err = daemon.ConnectRPC()
				if err == nil {
					break
				}
				time.Sleep(1 * time.Second)
			}
			if client == nil {
				return fmt.Errorf("failed to connect to daemon after starting it")
			}
		}
		defer client.Close()

		var reply bool
		err = client.Call("VaultDaemon.Unlock", bytePassword, &reply)
		if err != nil || !reply {
			return fmt.Errorf("unlock failed: %v", err)
		}

		fmt.Println("Vault unlocked. Daemon is managing the keys.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unlockCmd)
}
