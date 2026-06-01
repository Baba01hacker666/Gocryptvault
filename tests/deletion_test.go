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

func TestDistributedDeletion(t *testing.T) {
	caFile, certFile, keyFile := generateTestCerts(t)
	serverTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, true)
	clientTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, false)

	// 1. Start Coordinator
	coordAddr, _, stopCoord := startCoordinator(t, serverTLS)
	defer stopCoord()

	// 2. Start 6 Nodes
	var stopNodes []func()
	var nodeAddrs []string
	var nodeDirs []string
	for i := 0; i < 6; i++ {
		addr, dir, stop := startNode(t, fmt.Sprintf("node-%d", i), serverTLS)
		stopNodes = append(stopNodes, stop)
		nodeAddrs = append(nodeAddrs, addr)
		nodeDirs = append(nodeDirs, dir)
	}
	defer func() {
		for _, stop := range stopNodes {
			stop()
		}
	}()

	// 3. Register Nodes
	coordConn, _ := grpc.Dial(coordAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	defer coordConn.Close()
	coordClient := pb.NewCoordinatorClient(coordConn)

	for i, addr := range nodeAddrs {
		_, _ = coordClient.RegisterNode(context.Background(), &pb.NodeInfo{
			Id:            fmt.Sprintf("node-%d", i),
			Endpoint:      addr,
			CapacityBytes: 1024 * 1024 * 1024,
		})
	}

	// 4. Start a mock Daemon
	vDir := t.TempDir()
	v := storage.NewVault(vDir)
	pass := []byte("testpass")
	v.Init(pass)
	v.Unlock(pass)

	d := daemon.NewDaemon(v)
	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("VaultDaemon", d)
	socketPath := filepath.Join(t.TempDir(), "test-del.sock")
	l, _ := net.Listen("unix", socketPath)
	go rpcServer.Accept(l)
	defer l.Close()

	rpcClient, _ := rpc.Dial("unix", socketPath)
	defer rpcClient.Close()
	c := &client.Client{RPC: rpcClient}

	// 5. Upload a file
	testFile := filepath.Join(t.TempDir(), "test-del.dat")
	testData := []byte("Deletion test data")
	os.WriteFile(testFile, testData, 0644)

	err := c.AddFileDistributed(testFile, "delete-me.dat", coordAddr, clientTLS, false, "")
	if err != nil {
		t.Fatalf("AddFileDistributed failed: %v", err)
	}

	// Verify file exists
	files, _ := c.ListFilesDistributed(coordAddr, clientTLS, false, "")
	if len(files) == 0 {
		t.Fatal("File was not uploaded")
	}
	fileID := files[0].ID

	// 6. Delete the file
	err = c.DeleteFileDistributed(fileID, coordAddr, clientTLS, false, "")
	if err != nil {
		t.Fatalf("DeleteFileDistributed failed: %v", err)
	}

	// 7. Verify deletion from Coordinator
	filesAfter, _ := c.ListFilesDistributed(coordAddr, clientTLS, false, "")
	for _, f := range filesAfter {
		if f.ID == fileID {
			t.Error("File still exists in coordinator metadata after deletion")
		}
	}

	// 8. Verify deletion from Nodes
	foundShards := 0
	for _, dir := range nodeDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				foundShards++
			}
			return nil
		})
	}
	if foundShards > 0 {
		t.Errorf("Found %d shards on nodes after deletion, expected 0", foundShards)
	}
}

func TestDistributedDeletionWithRestart(t *testing.T) {
	caFile, certFile, keyFile := generateTestCerts(t)
	serverTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, true)
	clientTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, false)

	coordVaultDir := t.TempDir()
	coordAddr, _, stopCoord := startCoordinatorWithDir(t, serverTLS, coordVaultDir)
	
	// Start 6 nodes and register
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
	
	conn, _ := grpc.Dial(coordAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	coordClient := pb.NewCoordinatorClient(conn)
	for i, addr := range nodeAddrs {
		_, _ = coordClient.RegisterNode(context.Background(), &pb.NodeInfo{
			Id: fmt.Sprintf("node-%d", i), 
			Endpoint: addr,
			CapacityBytes: 1024 * 1024 * 1024,
		})
	}
	conn.Close()

	// Mock daemon and client...
	vDir := t.TempDir()
	v := storage.NewVault(vDir)
	pass := []byte("testpass")
	v.Init(pass)
	v.Unlock(pass)
	d := daemon.NewDaemon(v)
	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("VaultDaemon", d)
	socketPath := filepath.Join(t.TempDir(), "test-restart.sock")
	l, _ := net.Listen("unix", socketPath)
	go rpcServer.Accept(l)
	defer l.Close()
	rpcClient, _ := rpc.Dial("unix", socketPath)
	defer rpcClient.Close()
	c := &client.Client{RPC: rpcClient}

	// Upload
	testFile := filepath.Join(t.TempDir(), "test.dat")
	os.WriteFile(testFile, []byte("data for restart test"), 0644)
	if err := c.AddFileDistributed(testFile, "test.dat", coordAddr, clientTLS, false, ""); err != nil {
		t.Fatalf("AddFileDistributed failed: %v", err)
	}
	
	files, err := c.ListFilesDistributed(coordAddr, clientTLS, false, "")
	if err != nil || len(files) == 0 {
		t.Fatalf("ListFilesDistributed failed or returned 0 files: %v", err)
	}
	fileID := files[0].ID

	// Restart Coordinator
	stopCoord()
	coordAddrFinal, _, stopCoordFinal := startCoordinatorWithDir(t, serverTLS, coordVaultDir)
	defer stopCoordFinal()

	// Delete
	err = c.DeleteFileDistributed(fileID, coordAddrFinal, clientTLS, false, "")
	if err != nil {
		t.Fatalf("Delete failed after restart: %v", err)
	}

	// Restart again and verify tracking is GONE
	stopCoordFinal()
	_, _, stopCoordLast := startCoordinatorWithDir(t, serverTLS, coordVaultDir)
	defer stopCoordLast()
	
	shardsFile := filepath.Join(coordVaultDir, "shards.json")
	data, _ := os.ReadFile(shardsFile)
	if string(data) != "{}" {
		t.Errorf("shards.json not empty after deletion: %s", string(data))
	}
}
