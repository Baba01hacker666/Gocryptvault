package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/api/rest"
	"github.com/Baba01hacker666/Gocryptvault/internal/coordinator"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	coordAddr     string
	coordGRPCAddr string
	coordVault    string
	coordPKIDir   string
	coordCA       string
	coordCert     string
	coordKey      string
)

var coordinatorCmd = &cobra.Command{
	Use:   "coordinator",
	Short: "Start the distributed vault coordinator",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Auto-generate PKI if certs not explicitly provided
		var tlsConfig *tls.Config
		if coordCA == "" || coordCert == "" || coordKey == "" {
			var err error
			var bundle *security.PKIBundle
			// FIXED HIGH-08: extract hostname from --addr and include in cert SANs
			host, _, _ := net.SplitHostPort(coordAddr)
			opts := &security.PKIOptions{}
			if host != "" && host != "0.0.0.0" {
				if ip := net.ParseIP(host); ip != nil {
					opts.ExtraIPs = []net.IP{ip}
				} else {
					opts.ExtraSANs = []string{host}
				}
			}
			tlsConfig, bundle, err = security.LoadOrGenTLSConfig(coordPKIDir, true, opts)
			if err != nil {
				return fmt.Errorf("auto-PKI failed: %w", err)
			}
			_ = bundle
		} else {
			var err error
			tlsConfig, err = security.LoadTLSConfig(coordCA, coordCert, coordKey, true)
			if err != nil {
				return fmt.Errorf("failed to load TLS config: %w", err)
			}
		}


		registry := coordinator.NewRegistry()
		registry.StartEviction(context.Background(), 5*time.Minute)
		server := &coordinator.CoordinatorServer{
			Registry: registry,
			VaultDir: coordVault,
		}

		// HTTPS REST Server (Primary)
		httpServer := &http.Server{
			Addr:      coordAddr,
			TLSConfig: tlsConfig,
			Handler:   rest.NewRESTHandler(server),
		}

		go func() {
			fmt.Printf("Coordinator (HTTPS REST) listening on %s\n", coordAddr)
			if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server failed: %v", err)
			}
		}()

		// Optional gRPC Server (Disabled by default)
		if coordGRPCAddr != "" {
			grpcLis, err := net.Listen("tcp", coordGRPCAddr)
			if err != nil {
				return fmt.Errorf("failed to listen for gRPC: %w", err)
			}
			s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
			pb.RegisterCoordinatorServer(s, server)
			
			go func() {
				fmt.Printf("Coordinator (gRPC) listening on %s\n", coordGRPCAddr)
				if err := s.Serve(grpcLis); err != nil {
					log.Fatalf("gRPC server failed: %v", err)
				}
			}()
		}

		// Keep alive
		select {}
	},
}

func init() {
	coordinatorCmd.Flags().StringVar(&coordAddr, "addr", "0.0.0.0:50051", "Address to listen on for HTTPS REST API")
	coordinatorCmd.Flags().StringVar(&coordGRPCAddr, "grpc-addr", "", "Address to listen on for gRPC API (disabled by default, explicit separate port required)")
	coordinatorCmd.Flags().StringVar(&coordPKIDir, "pki-dir", "~/.gocryptvault/pki", "Directory for auto-generated PKI certs (used when --ca/--cert/--key are not set)")
	coordinatorCmd.Flags().StringVar(&coordVault, "vault-dir", "./coordinator_vault", "Directory to store encrypted metadata")
	coordinatorCmd.Flags().StringVar(&coordCA, "ca", "", "CA certificate file (auto-generated if not set)")
	coordinatorCmd.Flags().StringVar(&coordCert, "cert", "", "Server certificate file (auto-generated if not set)")
	coordinatorCmd.Flags().StringVar(&coordKey, "key", "", "Server private key file (auto-generated if not set)")

	rootCmd.AddCommand(coordinatorCmd)
}

