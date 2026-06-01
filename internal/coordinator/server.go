package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
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
	shardToNode := s.Registry.GetShardLocations(req.FileId)
	locs := make(map[string]string)
	for shardID, nodeID := range shardToNode {
		node := s.Registry.GetNode(nodeID)
		if node != nil {
			locs[shardID] = node.Endpoint
		} else {
			// Fallback: if nodeID is already an endpoint, use it directly
			locs[shardID] = nodeID
		}
	}
	return &pb.DownloadPlanResponse{Locations: locs}, nil
}

func (s *CoordinatorServer) GetMetadata(ctx context.Context, req *pb.GetMetadataRequest) (*pb.GetMetadataResponse, error) {
	path := filepath.Join(s.VaultDir, "metadata.enc")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return random noise if metadata does not exist (plausible deniability)
			noise := make([]byte, metadata.MetadataBlobSize)
			if _, err := rand.Read(noise); err != nil {
				return nil, fmt.Errorf("failed to generate random noise: %w", err)
			}
			return &pb.GetMetadataResponse{EncryptedDb: noise}, nil
		}
		return nil, err
	}
	return &pb.GetMetadataResponse{EncryptedDb: data}, nil
}

func (s *CoordinatorServer) UpdateMetadata(ctx context.Context, req *pb.UpdateMetadataRequest) (*pb.UpdateMetadataResponse, error) {
	if len(req.EncryptedDb) != metadata.MetadataBlobSize {
		return nil, fmt.Errorf("invalid metadata blob size: expected %d, got %d", metadata.MetadataBlobSize, len(req.EncryptedDb))
	}

	path := filepath.Join(s.VaultDir, "metadata.enc")
	if err := os.WriteFile(path, req.EncryptedDb, 0600); err != nil {
		return nil, err
	}

	for fileID, locations := range req.NewFileLocations {
		s.Registry.SetShardLocations(fileID, locations.ShardToNode)
	}

	// Persist shard locations
	if err := s.SaveState(); err != nil {
		return nil, err
	}

	return &pb.UpdateMetadataResponse{Success: true}, nil
}

func (s *CoordinatorServer) DeleteMetadata(ctx context.Context, req *pb.DeleteMetadataRequest) (*pb.DeleteMetadataResponse, error) {
	s.Registry.DeleteShardLocations(req.FileId)
	if err := s.SaveState(); err != nil {
		return nil, err
	}
	return &pb.DeleteMetadataResponse{Success: true}, nil
}

func (s *CoordinatorServer) SaveState() error {
	path := filepath.Join(s.VaultDir, "shards.json")
	s.Registry.mu.RLock()
	defer s.Registry.mu.RUnlock()
	data, err := json.Marshal(s.Registry.shardLocations)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (s *CoordinatorServer) LoadState() error {
	path := filepath.Join(s.VaultDir, "shards.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var locations map[string]map[string]string
	if err := json.Unmarshal(data, &locations); err != nil {
		return err
	}
	s.Registry.mu.Lock()
	defer s.Registry.mu.Unlock()
	s.Registry.shardLocations = locations
	return nil
}
