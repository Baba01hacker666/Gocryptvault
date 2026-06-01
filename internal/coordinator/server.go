package coordinator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
)

type CoordinatorServer struct {
	pb.UnimplementedCoordinatorServer
	Registry *Registry
	VaultDir string
}

func (s *CoordinatorServer) RegisterNode(ctx context.Context, req *pb.NodeInfo) (*pb.RegisterResponse, error) {
	s.Registry.Register(req.Id, req.Endpoint, req.CapacityBytes)
	return &pb.RegisterResponse{Success: true}, nil
}

func (s *CoordinatorServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.Registry.mu.Lock()
	if node, ok := s.Registry.nodes[req.NodeId]; ok {
		node.LastSeen = time.Now()
	}
	s.Registry.mu.Unlock()
	return &pb.HeartbeatResponse{Acknowledged: true}, nil
}

func (s *CoordinatorServer) GetUploadPlan(ctx context.Context, req *pb.UploadPlanRequest) (*pb.UploadPlanResponse, error) {
	nodes := s.Registry.GetHealthyNodes()
	if len(nodes) < int(req.ShardCount) {
		return nil, fmt.Errorf("insufficient healthy nodes (found %d, need %d)", len(nodes), req.ShardCount)
	}
	assignments := make(map[int32]string)
	for i := 0; i < int(req.ShardCount); i++ {
		assignments[int32(i)] = nodes[i%len(nodes)].Endpoint
	}
	return &pb.UploadPlanResponse{Assignments: assignments}, nil
}

func (s *CoordinatorServer) GetDownloadPlan(ctx context.Context, req *pb.DownloadPlanRequest) (*pb.DownloadPlanResponse, error) {
	// In a real impl, we'd lookup which nodes HAVE the shards for fileID from s.Registry.
	// For now, returning empty as proper tracking is in Task 2.
	locs := make(map[string]string)
	return &pb.DownloadPlanResponse{Locations: locs}, nil
}

func (s *CoordinatorServer) GetMetadata(ctx context.Context, req *pb.GetMetadataRequest) (*pb.GetMetadataResponse, error) {
	path := filepath.Join(s.VaultDir, "metadata.enc")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.GetMetadataResponse{EncryptedDb: nil}, nil
		}
		return nil, err
	}
	return &pb.GetMetadataResponse{EncryptedDb: data}, nil
}

func (s *CoordinatorServer) UpdateMetadata(ctx context.Context, req *pb.UpdateMetadataRequest) (*pb.UpdateMetadataResponse, error) {
	path := filepath.Join(s.VaultDir, "metadata.enc")
	if err := os.WriteFile(path, req.EncryptedDb, 0600); err != nil {
		return nil, err
	}
	return &pb.UpdateMetadataResponse{Success: true}, nil
}
