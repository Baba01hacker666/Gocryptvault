package cmd

import (
	"fmt"
	"log"
	"net"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/coordinator"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	coordAddr   string
	coordVault  string
	coordCA     string
	coordCert   string
	coordKey    string
)

var coordinatorCmd = &cobra.Command{
	Use:   "coordinator",
	Short: "Start the distributed vault coordinator",
	RunE: func(cmd *cobra.Command, args []string) error {
		tlsConfig, err := security.LoadTLSConfig(coordCA, coordCert, coordKey, true)
		if err != nil {
			return fmt.Errorf("failed to load TLS config: %w", err)
		}

		lis, err := net.Listen("tcp", coordAddr)
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		registry := coordinator.NewRegistry()
		server := &coordinator.CoordinatorServer{
			Registry: registry,
			VaultDir: coordVault,
		}

		s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
		pb.RegisterCoordinatorServer(s, server)

		fmt.Printf("Coordinator listening on %s\n", coordAddr)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
		return nil
	},
}

func init() {
	coordinatorCmd.Flags().StringVar(&coordAddr, "addr", "0.0.0.0:50051", "Address to listen on")
	coordinatorCmd.Flags().StringVar(&coordVault, "vault-dir", "./coordinator_vault", "Directory to store encrypted metadata")
	coordinatorCmd.Flags().StringVar(&coordCA, "ca", "ca.crt", "CA certificate file")
	coordinatorCmd.Flags().StringVar(&coordCert, "cert", "server.crt", "Server certificate file")
	coordinatorCmd.Flags().StringVar(&coordKey, "key", "server.key", "Server private key file")

	rootCmd.AddCommand(coordinatorCmd)
}
