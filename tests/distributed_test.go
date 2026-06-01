package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/coordinator"
	"github.com/Baba01hacker666/Gocryptvault/internal/node"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func generateTestCerts(t *testing.T) (caFile, certFile, keyFile string) {
	tempDir := t.TempDir()

	// CA
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Gocryptvault Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	caFile = filepath.Join(tempDir, "ca.crt")
	caOut, _ := os.Create(caFile)
	pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caOut.Close()

	// Cert/Key
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Gocryptvault Test Node"},
		},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caTemplate, &privKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certFile = filepath.Join(tempDir, "cert.crt")
	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyFile = filepath.Join(tempDir, "key.pem")
	keyOut, _ := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	keyOut.Close()

	return
}

func startCoordinator(t *testing.T, tlsConfig *tls.Config) (string, string, func()) {
	vaultDir := t.TempDir()
	registry := coordinator.NewRegistry()
	server := &coordinator.CoordinatorServer{
		Registry: registry,
		VaultDir: vaultDir,
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	pb.RegisterCoordinatorServer(s, server)

	go s.Serve(lis)

	return lis.Addr().String(), vaultDir, s.Stop
}

func startNode(t *testing.T, id string, tlsConfig *tls.Config) (string, string, func()) {
	baseDir := t.TempDir()
	server := &node.StorageServer{BaseDir: baseDir}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	pb.RegisterStorageNodeServer(s, server)

	go s.Serve(lis)

	return lis.Addr().String(), baseDir, s.Stop
}

func TestDistributedIntegration(t *testing.T) {
	caFile, certFile, keyFile := generateTestCerts(t)
	serverTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, true)
	clientTLS, _ := security.LoadTLSConfig(caFile, certFile, keyFile, false)

	// 1. Start Coordinator
	coordAddr, coordVaultDir, stopCoord := startCoordinator(t, serverTLS)
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

	// 3. Register Nodes with Coordinator
	coordConn, err := grpc.Dial(coordAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("failed to connect to coordinator: %v", err)
	}
	defer coordConn.Close()
	coordClient := pb.NewCoordinatorClient(coordConn)

	for i, addr := range nodeAddrs {
		_, err := coordClient.RegisterNode(context.Background(), &pb.NodeInfo{
			Id:            fmt.Sprintf("node-%d", i),
			Endpoint:      addr,
			CapacityBytes: 1024 * 1024 * 1024,
		})
		if err != nil {
			t.Fatalf("failed to register node %d: %v", i, err)
		}
	}

	// 4. Start a mock Daemon to satisfy Client dependencies
	vaultDir := t.TempDir()
	v := storage.NewVault(vaultDir)
	pass := []byte("testpass")
	v.Init(pass)
	v.Unlock(pass)

	d := daemon.NewDaemon(v)
	// We need to use a different name to avoid conflict if tests run in same process
	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("VaultDaemon", d)

	socketPath := filepath.Join(t.TempDir(), "test.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go rpcServer.Accept(l)
	defer l.Close()

	rpcClient, err := rpc.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rpcClient.Close()

	c := &client.Client{RPC: rpcClient}

	// 5. Test Distributed Upload
	testFile := filepath.Join(t.TempDir(), "test.dat")
	testData := []byte("This is a test file for distributed storage. It should be sharded and stored across 6 nodes.")
	os.WriteFile(testFile, testData, 0644)

	err = c.AddFileDistributed(testFile, "distributed-test.dat", coordAddr, clientTLS)
	if err != nil {
		t.Fatalf("AddFileDistributed failed: %v", err)
	}

	// 6. Verify Coordinator's metadata
	metaPath := filepath.Join(coordVaultDir, "metadata.enc")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Error("Coordinator metadata file not found")
	}

	// 7. Verify Shards on Nodes
	// We expect 6 shards total for the single chunk
	foundShards := 0
	for _, dir := range nodeDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				foundShards++
			}
			return nil
		})
	}
	if foundShards < 6 {
		t.Errorf("Expected at least 6 shards across nodes, found %d", foundShards)
	}

	// 8. Test Distributed Download/Export
	files, err := c.ListFilesDistributed(coordAddr, clientTLS)
	if err != nil {
		t.Fatalf("ListFilesDistributed failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No files found after upload")
	}
	fileID := files[0].ID

	outDir := t.TempDir()
	err = c.ExportFileDistributed(fileID, outDir, coordAddr, clientTLS)
	if err != nil {
		t.Fatalf("ExportFileDistributed failed: %v", err)
	}

	exportedFile := filepath.Join(outDir, "distributed-test.dat")
	exportedData, err := os.ReadFile(exportedFile)
	if err != nil {
		t.Fatalf("Failed to read exported file: %v", err)
	}
	if string(exportedData) != string(testData) {
		t.Errorf("Exported data mismatch. Got %q, want %q", exportedData, testData)
	}

	// 9. Test Fault Tolerance
	// Stop 2 nodes (4+2 means we can lose up to 2)
	stopNodes[0]()
	stopNodes[1]()
	
	t.Log("Testing fault tolerance (2 nodes down)...")
	outDir2 := t.TempDir()
	err = c.ExportFileDistributed(fileID, outDir2, coordAddr, clientTLS)
	if err != nil {
		t.Fatalf("ExportFileDistributed failed with 2 nodes down: %v", err)
	}

	exportedData2, _ := os.ReadFile(filepath.Join(outDir2, "distributed-test.dat"))
	if string(exportedData2) != string(testData) {
		t.Errorf("Exported data mismatch after failure. Got %q, want %q", exportedData2, testData)
	}
}
