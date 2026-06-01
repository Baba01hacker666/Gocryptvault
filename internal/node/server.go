package node

import (
	"context"
	"io"
	"os"
	"path/filepath"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
)

type StorageServer struct {
	pb.UnimplementedStorageNodeServer
	BaseDir string
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
			path := filepath.Join(s.BaseDir, shardID[:2], shardID)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			f, err = os.Create(path)
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
	path := filepath.Join(s.BaseDir, req.ShardId[:2], req.ShardId)
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

func (s *StorageServer) DeleteShard(ctx context.Context, req *pb.ShardRequest) (*pb.DeleteResponse, error) {
	path := filepath.Join(s.BaseDir, req.ShardId[:2], req.ShardId)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return &pb.DeleteResponse{Success: true}, nil
		}
		return nil, err
	}
	return &pb.DeleteResponse{Success: true}, nil
}
