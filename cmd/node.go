package cmd

import (
	"context"
	"fmt"
	"log"
	"net"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/node"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	nodeAddr      string
	nodeDir       string
	nodeCA        string
	nodeCert      string
	nodeKey       string
	nodeID        string
	nodeCoordAddr string
	nodeRegister  bool
)

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Start a distributed vault storage node",
	RunE: func(cmd *cobra.Command, args []string) error {
		tlsConfig, err := security.LoadTLSConfig(nodeCA, nodeCert, nodeKey, true)
		if err != nil {
			return fmt.Errorf("failed to load TLS config: %w", err)
		}

		if nodeRegister {
			clientTLS, err := security.LoadTLSConfig(nodeCA, nodeCert, nodeKey, false)
			if err != nil {
				return fmt.Errorf("failed to load client TLS config: %w", err)
			}
			
			conn, err := grpc.Dial(nodeCoordAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
			if err != nil {
				return fmt.Errorf("failed to connect to coordinator for registration: %w", err)
			}
			defer conn.Close()
			
			coord := pb.NewCoordinatorClient(conn)
			_, err = coord.RegisterNode(context.Background(), &pb.NodeInfo{
				Id:            nodeID,
				Endpoint:      nodeAddr,
				CapacityBytes: 10 * 1024 * 1024 * 1024, // 10GB default
			})
			if err != nil {
				return fmt.Errorf("registration failed: %w", err)
			}
			fmt.Printf("Node %s registered with coordinator at %s\n", nodeID, nodeCoordAddr)
		}

		lis, err := net.Listen("tcp", nodeAddr)
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		server := &node.StorageServer{
			BaseDir: nodeDir,
		}

		s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
		pb.RegisterStorageNodeServer(s, server)

		fmt.Printf("Storage Node %s listening on %s\n", nodeID, nodeAddr)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
		return nil
	},
}

func init() {
	nodeCmd.Flags().StringVar(&nodeAddr, "addr", "0.0.0.0:50052", "Address to listen on")
	nodeCmd.Flags().StringVar(&nodeDir, "data-dir", "./node_data", "Directory to store encrypted shards")
	nodeCmd.Flags().StringVar(&nodeCA, "ca", "ca.crt", "CA certificate file")
	nodeCmd.Flags().StringVar(&nodeCert, "cert", "node.crt", "Node certificate file")
	nodeCmd.Flags().StringVar(&nodeKey, "key", "node.key", "Node private key file")
	nodeCmd.Flags().StringVar(&nodeID, "id", "node-1", "Unique ID for this node")
	nodeCmd.Flags().StringVar(&nodeCoordAddr, "coordinator", "127.0.0.1:50051", "Coordinator address for registration")
	nodeCmd.Flags().BoolVar(&nodeRegister, "register", false, "Register with coordinator on startup")

	rootCmd.AddCommand(nodeCmd)
}
