package coordinator

import (
	"context"
	"os"
	"testing"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
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

	// Test GetDownloadPlan
	downReq := &pb.DownloadPlanRequest{FileId: "file-1"}
	downRes, err := server.GetDownloadPlan(ctx, downReq)
	if err != nil {
		t.Fatalf("GetDownloadPlan failed: %v", err)
	}
	if len(downRes.Locations) == 0 {
		t.Error("GetDownloadPlan returned no locations")
	}

	// Test UpdateMetadata
	metaReq := &pb.UpdateMetadataRequest{EncryptedDb: []byte("test-data")}
	metaRes, err := server.UpdateMetadata(ctx, metaReq)
	if err != nil {
		t.Fatalf("UpdateMetadata failed: %v", err)
	}
	if !metaRes.Success {
		t.Error("UpdateMetadata returned success=false")
	}
}
