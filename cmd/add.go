package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/spf13/cobra"
)

var (
	asyncAdd         bool
	distAdd          bool
	distCoordAddr    string
	distCA           string
	distCert         string
	distKey          string
	distHidden       bool
	distHiddenPass   string
)

var addCmd = &cobra.Command{
	Use:   "add [file_or_directory]",
	Short: "Add a file or directory to the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]
		targetPath = filepath.Clean(targetPath)

		info, err := os.Stat(targetPath)
		if err != nil {
			return err
		}

		if distAdd {
			tlsConfig, err := security.LoadTLSConfig(distCA, distCert, distKey, false)
			if err != nil {
				return fmt.Errorf("failed to load TLS config: %w", err)
			}

			c, err := client.NewClient()
			if err != nil {
				return fmt.Errorf("failed to connect to daemon: %w", err)
			}
			defer c.Close()

			if info.IsDir() {
				return fmt.Errorf("distributed directory upload not yet implemented")
			}

			fmt.Printf("Adding file %s in distributed mode...\n", targetPath)
			if err := c.AddFileDistributed(targetPath, filepath.Base(targetPath), distCoordAddr, tlsConfig, distHidden, distHiddenPass); err != nil {
				return fmt.Errorf("distributed add failed: %w", err)
			}
			fmt.Println("File added successfully in distributed mode.")
			return nil
		}

		v := getVault()

		if info.IsDir() {
			fmt.Printf("Adding directory %s...\n", targetPath)
			err := filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}

				relPath, err := filepath.Rel(filepath.Dir(targetPath), path)
				if err != nil {
					return err
				}

				if asyncAdd {
					errChan := v.AddFileAsync(path, relPath)
					err = <-errChan
					if err != nil {
						return fmt.Errorf("failed to add file %s asynchronously: %w", path, err)
					}
				} else {
					if err := v.AddFile(path, relPath); err != nil {
						return fmt.Errorf("failed to add file %s: %w", path, err)
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to add directory: %w", err)
			}
			fmt.Println("Directory added successfully.")
		} else {
			if asyncAdd {
				fmt.Println("Adding file asynchronously...")
				errChan := v.AddFileAsync(targetPath, filepath.Base(targetPath))
				err := <-errChan
				if err != nil {
					return fmt.Errorf("failed to add file asynchronously: %w", err)
				}
				fmt.Println("File added successfully.")
			} else {
				if err := v.AddFile(targetPath, filepath.Base(targetPath)); err != nil {
					return fmt.Errorf("failed to add file: %w", err)
				}
				fmt.Println("File added successfully.")
			}
		}

		return nil
	},
}

func init() {
	addCmd.Flags().BoolVar(&asyncAdd, "async", false, "Add file asynchronously")
	addCmd.Flags().BoolVar(&distAdd, "distributed", false, "Use distributed mode")
	addCmd.Flags().StringVar(&distCoordAddr, "coordinator", "127.0.0.1:50051", "Coordinator address")
	addCmd.Flags().StringVar(&distCA, "ca", "ca.crt", "CA certificate for distributed mode")
	addCmd.Flags().StringVar(&distCert, "cert", "client.crt", "Client certificate for distributed mode")
	addCmd.Flags().StringVar(&distKey, "key", "client.key", "Client key for distributed mode")
	addCmd.Flags().BoolVar(&distHidden, "hidden", false, "Use hidden vault")
	addCmd.Flags().StringVar(&distHiddenPass, "hidden-password", "", "Password for hidden vault")

	rootCmd.AddCommand(addCmd)
}
