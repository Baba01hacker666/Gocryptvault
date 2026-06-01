package coordinator

import (
	"context"
	"os"
	"testing"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
)

func TestCoordinatorServer(t *testing.T) {
	vaultDir, err := os.MkdirTemp("", "coordinator-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(vaultDir)

	registry := NewRegistry()
	server := &CoordinatorServer{
		Registry: registry,
		VaultDir: vaultDir,
	}

	ctx := context.Background()

	// Test GetMetadata returns noise when not initialized
	getRes, err := server.GetMetadata(ctx, &pb.GetMetadataRequest{})
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if len(getRes.EncryptedDb) != metadata.MetadataBlobSize {
		t.Errorf("expected %d bytes of noise, got %d", metadata.MetadataBlobSize, len(getRes.EncryptedDb))
	}

	// Test RegisterNode
	regReq := &pb.NodeInfo{
		Id:            "node-1",
		Endpoint:      "localhost:5001",
		CapacityBytes: 1024,
	}
	regRes, err := server.RegisterNode(ctx, regReq)
	if err != nil {
		t.Fatalf("RegisterNode failed: %v", err)
	}
	if !regRes.Success {
		t.Error("RegisterNode returned success=false")
	}

	// Test Heartbeat
	hbReq := &pb.HeartbeatRequest{NodeId: "node-1"}
	hbRes, err := server.Heartbeat(ctx, hbReq)
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
	if !hbRes.Acknowledged {
		t.Error("Heartbeat returned acknowledged=false")
	}

	// Test GetUploadPlan
	upReq := &pb.UploadPlanRequest{ShardCount: 1}
	upRes, err := server.GetUploadPlan(ctx, upReq)
	if err != nil {
		t.Fatalf("GetUploadPlan failed: %v", err)
	}
	if len(upRes.Assignments) != 1 || upRes.Assignments[0] != "localhost:5001" {
		t.Errorf("Unexpected upload assignments: %v", upRes.Assignments)
	}

	// Test UpdateMetadata with shard locations
	testBlob := make([]byte, metadata.MetadataBlobSize)
	copy(testBlob, "test-data")
	metaReq := &pb.UpdateMetadataRequest{
		EncryptedDb: testBlob,
		NewFileLocations: map[string]*pb.ShardLocations{
			"file-1": {
				ShardToNode: map[string]string{
					"shard-0": "node-1",
				},
			},
		},
	}
	metaRes, err := server.UpdateMetadata(ctx, metaReq)
	if err != nil {
		t.Fatalf("UpdateMetadata failed: %v", err)
	}
	if !metaRes.Success {
		t.Error("UpdateMetadata returned success=false")
	}

	// Test UpdateMetadata with invalid size
	badReq := &pb.UpdateMetadataRequest{
		EncryptedDb: []byte("too-small"),
	}
	_, err = server.UpdateMetadata(ctx, badReq)
	if err == nil {
		t.Error("expected error for small metadata blob, got nil")
	}

	// Test GetDownloadPlan
	downReq := &pb.DownloadPlanRequest{FileId: "file-1"}
	downRes, err := server.GetDownloadPlan(ctx, downReq)
	if err != nil {
		t.Fatalf("GetDownloadPlan failed: %v", err)
	}
	if len(downRes.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(downRes.Locations))
	}
	if downRes.Locations["shard-0"] != "localhost:5001" {
		t.Errorf("expected localhost:5001 for shard-0, got %s", downRes.Locations["shard-0"])
	}
}
