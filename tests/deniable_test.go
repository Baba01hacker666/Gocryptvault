package tests

import (
	"context"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestDeniableVaultIntegration(t *testing.T) {
	caFile, certFile, keyFile := generateTestCerts(t)
	serverTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, true)
	clientTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, false)

	// 1. Start Coordinator
	coordVaultDir := t.TempDir()
	coordAddr, _, stopCoord := startCoordinatorWithDir(t, serverTLS, coordVaultDir)
	defer stopCoord()

	// 2. Start Nodes
	var stopNodes []func()
	var nodeAddrs []string
	for i := 0; i < 6; i++ {
		addr, _, stop := startNode(t, fmt.Sprintf("node-%d", i), serverTLS)
		stopNodes = append(stopNodes, stop)
		nodeAddrs = append(nodeAddrs, addr)
	}
	defer func() {
		for _, stop := range stopNodes {
			stop()
		}
	}()

	// 3. Register Nodes
	coordConn, _ := grpc.Dial(coordAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	coordClient := pb.NewCoordinatorClient(coordConn)
	for i, addr := range nodeAddrs {
		_, _ = coordClient.RegisterNode(context.Background(), &pb.NodeInfo{
			Id:            fmt.Sprintf("node-%d", i),
			Endpoint:      addr,
			CapacityBytes: 1024 * 1024 * 1024,
		})
	}
	coordConn.Close()

	// 4. Mock Daemon for client dependencies
	vDir := t.TempDir()
	v := storage.NewVault(vDir)
	pass := []byte("decoy_password") // Main session uses decoy
	v.Init(pass)
	v.Unlock(pass)

	d := daemon.NewDaemon(v)
	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("VaultDaemon", d)
	socketPath := filepath.Join(t.TempDir(), "test-deniable.sock")
	l, _ := net.Listen("unix", socketPath)
	go rpcServer.Accept(l)
	defer l.Close()

	rpcClient, _ := rpc.Dial("unix", socketPath)
	defer rpcClient.Close()
	c := &client.Client{RPC: rpcClient}

	hiddenPassword := "hidden_secret_password"

	// 5. Add to Decoy Vault
	decoyFile := filepath.Join(t.TempDir(), "decoy.txt")
	os.WriteFile(decoyFile, []byte("boring decoy data"), 0644)
	if err := c.AddFileDistributed(decoyFile, "decoy.txt", coordAddr, clientTLS, false, ""); err != nil {
		t.Fatalf("AddFileDistributed (decoy) failed: %v", err)
	}

	// 6. Add to Hidden Vault
	hiddenFile := filepath.Join(t.TempDir(), "hidden.txt")
	os.WriteFile(hiddenFile, []byte("very secret hidden data"), 0644)
	if err := c.AddFileDistributed(hiddenFile, "hidden.txt", coordAddr, clientTLS, true, hiddenPassword); err != nil {
		t.Fatalf("AddFileDistributed (hidden) failed: %v", err)
	}

	// 7. Verify List Decoy
	decoyFiles, err := c.ListFilesDistributed(coordAddr, clientTLS, false, "")
	if err != nil {
		t.Fatalf("ListFilesDistributed (decoy) failed: %v", err)
	}
	if len(decoyFiles) != 1 || decoyFiles[0].Filename != "decoy.txt" {
		t.Errorf("Expected 1 decoy file, got %v", len(decoyFiles))
	}

	// 8. Verify List Hidden
	hiddenFiles, err := c.ListFilesDistributed(coordAddr, clientTLS, true, hiddenPassword)
	if err != nil {
		t.Fatalf("ListFilesDistributed (hidden) failed: %v", err)
	}
	if len(hiddenFiles) != 1 || hiddenFiles[0].Filename != "hidden.txt" {
		t.Errorf("Expected 1 hidden file, got %v", len(hiddenFiles))
	}

	// 9. Verify Export Decoy
	outDir := t.TempDir()
	if err := c.ExportFileDistributed(decoyFiles[0].ID, outDir, coordAddr, clientTLS, false, ""); err != nil {
		t.Fatalf("ExportFileDistributed (decoy) failed: %v", err)
	}
	extractedDecoy, _ := os.ReadFile(filepath.Join(outDir, "decoy.txt"))
	if string(extractedDecoy) != "boring decoy data" {
		t.Errorf("Exported decoy data mismatch")
	}

	// 10. Verify Export Hidden
	outDirHidden := t.TempDir()
	if err := c.ExportFileDistributed(hiddenFiles[0].ID, outDirHidden, coordAddr, clientTLS, true, hiddenPassword); err != nil {
		t.Fatalf("ExportFileDistributed (hidden) failed: %v", err)
	}
	extractedHidden, _ := os.ReadFile(filepath.Join(outDirHidden, "hidden.txt"))
	if string(extractedHidden) != "very secret hidden data" {
		t.Errorf("Exported hidden data mismatch")
	}

	// 11. Verify Delete Hidden
	if err := c.DeleteFileDistributed(hiddenFiles[0].ID, coordAddr, clientTLS, true, hiddenPassword); err != nil {
		t.Fatalf("DeleteFileDistributed (hidden) failed: %v", err)
	}

	// Verify hidden file is gone but decoy remains
	hiddenFilesAfter, _ := c.ListFilesDistributed(coordAddr, clientTLS, true, hiddenPassword)
	if len(hiddenFilesAfter) != 0 {
		t.Errorf("Hidden file still exists after deletion")
	}

	decoyFilesAfter, _ := c.ListFilesDistributed(coordAddr, clientTLS, false, "")
	if len(decoyFilesAfter) != 1 {
		t.Errorf("Decoy file was unexpectedly deleted")
	}
}
