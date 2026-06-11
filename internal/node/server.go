package node

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
)

// shardIDRegex enforces that a ShardId is exactly 64 lowercase hex chars (SHA-256).
// FIXED CRIT-03: prevents path traversal via malicious ShardId values.
var shardIDRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type StorageServer struct {
	pb.UnimplementedStorageNodeServer
	BaseDir string
}

// validateShardID returns the safe on-disk path for a shard, or an error if
// the shard ID is malformed or the resulting path escapes BaseDir.
func (s *StorageServer) validateShardID(shardID string) (string, error) {
	if !shardIDRegex.MatchString(shardID) {
		return "", fmt.Errorf("invalid shard ID format: must be 64 lowercase hex characters")
	}
	path := filepath.Join(s.BaseDir, shardID[:2], shardID)

	// Belt-and-suspenders: confirm path stays under BaseDir
	absBase, err := filepath.Abs(s.BaseDir)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if len(absPath) <= len(absBase) || absPath[:len(absBase)+1] != absBase+string(filepath.Separator) {
		return "", fmt.Errorf("shard path escapes base directory")
	}
	return path, nil
}

func (s *StorageServer) PutShard(stream pb.StorageNode_PutShardServer) error {
	var shardID string
	var f *os.File

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			if f != nil {
				f.Close()
			}
			return stream.SendAndClose(&pb.PutResponse{Success: true})
		}
		if err != nil {
			if f != nil {
				f.Close()
			}
			return err
		}

		if f == nil {
			shardID = chunk.ShardId
			path, err := s.validateShardID(shardID)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
		}
		if _, err := f.Write(chunk.Data); err != nil {
			f.Close()
			return err
		}
	}
}

func (s *StorageServer) GetShard(req *pb.ShardRequest, stream pb.StorageNode_GetShardServer) error {
	path, err := s.validateShardID(req.ShardId)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.ShardChunk{Data: buf[:n]}); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// FIXED HIGH-05: securely overwrite shard data before unlinking.
func (s *StorageServer) DeleteShard(ctx context.Context, req *pb.ShardRequest) (*pb.DeleteResponse, error) {
	path, err := s.validateShardID(req.ShardId)
	if err != nil {
		return nil, err
	}

	// Secure wipe: overwrite with zeros before removal.
	// Note: on SSDs with wear-leveling this is best-effort (see MED-01).
	if info, err := os.Stat(path); err == nil {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0600); err == nil {
			zeros := make([]byte, info.Size())
			_, _ = f.Write(zeros)
			_ = f.Sync()
			f.Close()
		}
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return &pb.DeleteResponse{Success: true}, nil
		}
		return nil, err
	}
	return &pb.DeleteResponse{Success: true}, nil
}
