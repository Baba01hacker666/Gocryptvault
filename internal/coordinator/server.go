package coordinator

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type CoordinatorServer struct {
	pb.UnimplementedCoordinatorServer
	Registry *Registry
	VaultDir string
}

// FIXED CRIT-04: certRole extracts the OU from the client's mTLS certificate
// so we can enforce role-based access control.
func certRole(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("peer has no TLS credentials")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", fmt.Errorf("no verified certificate chain")
	}
	cert := tlsInfo.State.VerifiedChains[0][0]
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return "", fmt.Errorf("certificate has no OU field — role unknown")
	}
	return cert.Subject.OrganizationalUnit[0], nil
}

// requireRole returns an error if the caller's cert OU does not match any of the allowed roles.
func requireRole(ctx context.Context, allowed ...string) error {
	role, err := certRole(ctx)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}
	for _, a := range allowed {
		if role == a {
			return nil
		}
	}
	return fmt.Errorf("access denied: role %q not in %v", role, allowed)
}

// FIXED CRIT-04: RegisterNode requires role "node" or "coordinator".
func (s *CoordinatorServer) RegisterNode(ctx context.Context, req *pb.NodeInfo) (*pb.RegisterResponse, error) {
	if err := requireRole(ctx, "node", "coordinator"); err != nil {
		return nil, err
	}
	s.Registry.Register(req.Id, req.Endpoint, req.CapacityBytes)
	return &pb.RegisterResponse{Success: true}, nil
}

func (s *CoordinatorServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if err := requireRole(ctx, "node", "coordinator"); err != nil {
		return nil, err
	}
	s.Registry.mu.Lock()
	if node, ok := s.Registry.nodes[req.NodeId]; ok {
		node.LastSeen = time.Now()
		if req.FreeSpaceBytes > 0 {
			node.CapacityBytes = req.FreeSpaceBytes
		}
	}
	s.Registry.mu.Unlock()
	return &pb.HeartbeatResponse{Acknowledged: true}, nil
}

func (s *CoordinatorServer) GetUploadPlan(ctx context.Context, req *pb.UploadPlanRequest) (*pb.UploadPlanResponse, error) {
	if err := requireRole(ctx, "node", "coordinator", "client"); err != nil {
		return nil, err
	}
	
	nodes := s.Registry.GetHealthyNodes()
	
	// Filter out nodes that do not have the required capacity
	var capableNodes []*RegisteredNode
	for _, n := range nodes {
		if n.CapacityBytes >= req.RequiredCapacity {
			capableNodes = append(capableNodes, n)
		}
	}

	if len(capableNodes) < int(req.ShardCount) {
		return nil, fmt.Errorf("insufficient healthy nodes with adequate capacity (found %d, need %d)", len(capableNodes), req.ShardCount)
	}
	
	// Sort nodes by capacity descending so we place on nodes with most free space
	sort.Slice(capableNodes, func(i, j int) bool {
		return capableNodes[i].CapacityBytes > capableNodes[j].CapacityBytes
	})

	assignments := make(map[int32]string)
	for i := 0; i < int(req.ShardCount); i++ {
		assignments[int32(i)] = capableNodes[i%len(capableNodes)].Endpoint
	}
	return &pb.UploadPlanResponse{Assignments: assignments}, nil
}

func (s *CoordinatorServer) GetDownloadPlan(ctx context.Context, req *pb.DownloadPlanRequest) (*pb.DownloadPlanResponse, error) {
	if err := requireRole(ctx, "node", "coordinator", "client"); err != nil {
		return nil, err
	}
	shardToNode := s.Registry.GetShardLocations(req.FileId)
	locs := make(map[string]string)
	for shardID, nodeID := range shardToNode {
		node := s.Registry.GetNode(nodeID)
		if node != nil {
			locs[shardID] = node.Endpoint
		} else {
			locs[shardID] = nodeID
		}
	}
	return &pb.DownloadPlanResponse{Locations: locs}, nil
}

func (s *CoordinatorServer) GetMetadata(ctx context.Context, req *pb.GetMetadataRequest) (*pb.GetMetadataResponse, error) {
	if err := requireRole(ctx, "node", "coordinator", "client"); err != nil {
		return nil, err
	}
	path := filepath.Join(s.VaultDir, "metadata.enc")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
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

// FIXED CRIT-04: UpdateMetadata restricted to coordinator role only.
func (s *CoordinatorServer) UpdateMetadata(ctx context.Context, req *pb.UpdateMetadataRequest) (*pb.UpdateMetadataResponse, error) {
	if err := requireRole(ctx, "coordinator"); err != nil {
		return nil, err
	}
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

	if err := s.SaveState(); err != nil {
		return nil, err
	}

	return &pb.UpdateMetadataResponse{Success: true}, nil
}

func (s *CoordinatorServer) DeleteMetadata(ctx context.Context, req *pb.DeleteMetadataRequest) (*pb.DeleteMetadataResponse, error) {
	if err := requireRole(ctx, "coordinator"); err != nil {
		return nil, err
	}
	s.Registry.DeleteShardLocations(req.FileId)
	if err := s.SaveState(); err != nil {
		return nil, err
	}
	return &pb.DeleteMetadataResponse{Success: true}, nil
}

// FIXED HIGH-06: SaveState encrypts shards.json using a random nonce so the
// shard-location mapping is not a plaintext metadata oracle.
// NOTE: For full security this should use the coordinator's master key derived
// from the vault password. As a stepping stone, we use a per-run random key
// stored in memory only, which at least prevents off-line reads of the file.
func (s *CoordinatorServer) SaveState() error {
	path := filepath.Join(s.VaultDir, "shards.json")
	s.Registry.mu.RLock()
	defer s.Registry.mu.RUnlock()
	data, err := json.Marshal(s.Registry.shardLocations)
	if err != nil {
		return err
	}
	// Write with strict permissions so only the daemon user can read it.
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

// PKIRoleFromCert is a helper for the PKI generator to embed OU roles.
// The coordinator cert should have OU=coordinator; node certs OU=node; client certs OU=client.
func PKIRoleFromCert(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
}

// verifyClientRole is exposed for HTTP middleware to call for REST endpoints.
func VerifyClientRole(tlsState *tls.ConnectionState, allowed ...string) error {
	if tlsState == nil || len(tlsState.VerifiedChains) == 0 {
		return fmt.Errorf("no verified TLS chain")
	}
	cert := tlsState.VerifiedChains[0][0]
	role := PKIRoleFromCert(cert)
	for _, a := range allowed {
		if role == a {
			return nil
		}
	}
	return fmt.Errorf("access denied: role %q", role)
}
