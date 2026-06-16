package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/spf13/cobra"
)

var (
	csCoordAddr string
	csCA        string
	csCert      string
	csKey       string
)

var clusterStatusCmd = &cobra.Command{
	Use:   "cluster-status",
	Short: "Show healthy nodes in the distributed cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		tlsConfig, err := security.LoadTLSConfig(csCA, csCert, csKey, false)
		if err != nil {
			return fmt.Errorf("failed to load TLS config: %w", err)
		}

		// S2: GetClusterStatus is now a standalone function
		nodes, err := client.GetClusterStatus(csCoordAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to get cluster status: %w", err)
		}

		fmt.Printf("Coordinator: %s\n", csCoordAddr)
		fmt.Printf("Healthy Nodes: %d\n\n", len(nodes))

		if len(nodes) > 0 {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "NODE ID\tENDPOINT\tFREE SPACE\tLAST SEEN")
			for _, n := range nodes {
				fmt.Fprintf(w, "%s\t%s\t%d MB\t%s\n", n.ID, n.Endpoint, n.CapacityBytes/(1024*1024), n.LastSeen)
			}
			w.Flush()
		}

		return nil
	},
}

func init() {
	clusterStatusCmd.Flags().StringVar(&csCoordAddr, "coordinator", "127.0.0.1:8443", "Coordinator address")
	clusterStatusCmd.Flags().StringVar(&csCA, "ca", "ca.crt", "CA certificate")
	clusterStatusCmd.Flags().StringVar(&csCert, "cert", "client.crt", "Client certificate")
	clusterStatusCmd.Flags().StringVar(&csKey, "key", "client.key", "Client key")

	rootCmd.AddCommand(clusterStatusCmd)
}
