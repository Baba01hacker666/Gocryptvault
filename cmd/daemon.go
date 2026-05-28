package cmd

import (
	"fmt"
	"log"

	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start the vault daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Only run if not already running
		client, err := daemon.ConnectRPC()
		if err == nil {
			client.Close()
			fmt.Println("Daemon is already running.")
			return nil
		}

		fmt.Println("Starting vault daemon in foreground...")
		if err := daemon.RunServer(); err != nil {
			log.Fatalf("Daemon error: %v", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(daemonCmd)
}
