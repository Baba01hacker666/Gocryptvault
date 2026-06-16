package node

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func initGRPC(t *testing.T, baseDir string) pb.StorageNodeClient {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	pb.RegisterStorageNodeServer(s, &StorageServer{BaseDir: baseDir})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough://bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	return pb.NewStorageNodeClient(conn)
}

func TestStorageServer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "node_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	client := initGRPC(t, tmpDir)

	shardID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	data := []byte("hello world")

	// Test PutShard
	stream, err := client.PutShard(context.Background())
	if err != nil {
		t.Fatalf("PutShard failed: %v", err)
	}
	err = stream.Send(&pb.ShardChunk{
		ShardId: shardID,
		Data:    data,
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv failed: %v", err)
	}
	if !resp.Success {
		t.Error("PutShard unsuccessful")
	}

	// Test GetShard
	getStream, err := client.GetShard(context.Background(), &pb.ShardRequest{ShardId: shardID})
	if err != nil {
		t.Fatalf("GetShard failed: %v", err)
	}
	var receivedData []byte
	for {
		chunk, err := getStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv failed: %v", err)
		}
		receivedData = append(receivedData, chunk.Data...)
	}
	if string(receivedData) != string(data) {
		t.Errorf("Expected %s, got %s", data, receivedData)
	}

	// Test DeleteShard
	delResp, err := client.DeleteShard(context.Background(), &pb.ShardRequest{ShardId: shardID})
	if err != nil {
		t.Fatalf("DeleteShard failed: %v", err)
	}
	if !delResp.Success {
		t.Error("DeleteShard unsuccessful")
	}

	// Verify deletion
	_, err = os.Stat(tmpDir + "/te/" + shardID)
	if !os.IsNotExist(err) {
		t.Error("File still exists after deletion")
	}
}
