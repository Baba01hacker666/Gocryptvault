package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"github.com/Baba01hacker666/Gocryptvault/internal/objects"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (c *Client) AddFileDistributed(sourcePath, logicalName string, coordinatorAddr string, tlsConfig *tls.Config) error {
	// 1. Ensure we have keys (session)
	sess, err := session.GetSession()
	if err != nil {
		// Try to get from daemon
		if err := c.ensureSession(); err != nil {
			return err
		}
		sess, _ = session.GetSession()
	}

	// 2. Read local file
	f, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	// Detect MIME type
	mimeBuf := make([]byte, 512)
	n, _ := f.Read(mimeBuf)
	mimeType := http.DetectContentType(mimeBuf[:n])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// 3. Connect to Coordinator
	conn, err := grpc.Dial(coordinatorAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return fmt.Errorf("failed to connect to coordinator: %w", err)
	}
	defer conn.Close()
	coordinator := pb.NewCoordinatorClient(conn)

	// 4. Encrypt and Shard locally
	masterKey := sess.GetMasterKey()
	
	// For simplicity in this task, we process the whole file. 
	// In a real impl, we'd do it chunk by chunk like in storage.go.
	// But let's follow the storage.go pattern for consistency.
	
	numChunks := int((info.Size() + int64(objects.ChunkSize) - 1) / int64(objects.ChunkSize))
	if numChunks == 0 { numChunks = 1 }

	record := &types.FileRecord{
		ID: fmt.Sprintf("%d", time.Now().UnixNano()), // Simple ID for now
		Filename: func() string {
			if logicalName != "" { return logicalName }
			return filepath.Base(sourcePath)
		}(),
		Size:       info.Size(),
		MimeType:   mimeType,
		Compressed: true,
		Created:    time.Now().Unix(),
		Modified:   info.ModTime().Unix(),
		Chunks:     make([]types.ChunkInfo, numChunks),
	}

	// We'll use a semaphore to limit concurrent uploads
	limit := make(chan struct{}, 4)

	for i := 0; i < numChunks; i++ {
		buf := make([]byte, objects.ChunkSize)
		n, err := f.Read(buf)
		if n == 0 && err == io.EOF && i > 0 { break }
		if err != nil && err != io.EOF { return err }

		data := buf[:n]
		
		// Get upload plan for this chunk's shards
		// objects.DataShards + objects.ParityShards = 6
		planReq := &pb.UploadPlanRequest{ShardCount: int32(objects.DataShards + objects.ParityShards)}
		plan, err := coordinator.GetUploadPlan(context.Background(), planReq)
		if err != nil {
			return fmt.Errorf("failed to get upload plan: %w", err)
		}

		shards, ciphertextSize, err := objects.EncryptAndShard(data, masterKey)
		if err != nil {
			return err
		}

		chunkInfo := types.ChunkInfo{
			Index:  i,
			Size:   ciphertextSize,
			Shards: make([]types.ShardInfo, len(shards)),
		}

		var wg sync.WaitGroup
		shardErrors := make(chan error, len(shards))

		for j, shard := range shards {
			shardID := objects.ShardID(shard)
			nodeEndpoint := plan.Assignments[int32(j)]
			
			chunkInfo.Shards[j] = types.ShardInfo{
				Index:   j,
				ShardID: shardID,
				NodeID:  nodeEndpoint, // Using endpoint as NodeID for now
			}

			wg.Add(1)
			go func(idx int, sData []byte, sID string, endpoint string) {
				defer wg.Done()
				limit <- struct{}{}
				defer func() { <-limit }()

				if err := c.uploadShard(endpoint, sID, sData, tlsConfig); err != nil {
					shardErrors <- fmt.Errorf("shard %d upload failed: %w", idx, err)
				}
			}(j, shard, shardID, nodeEndpoint)
		}

		wg.Wait()
		close(shardErrors)
		for err := range shardErrors {
			if err != nil { return err }
		}

		record.Chunks[i] = chunkInfo
	}

	// 5. Update Metadata
	resp, err := coordinator.GetMetadata(context.Background(), &pb.GetMetadataRequest{})
	var db *metadata.MetadataDB
	if err == nil && resp != nil && resp.EncryptedDb != nil {
		db, err = metadata.DecryptMetadata(resp.EncryptedDb, sess.GetMetaKey())
		if err != nil {
			return fmt.Errorf("failed to decrypt metadata from coordinator: %w", err)
		}
	} else {
		db = metadata.NewMetadataDB()
	}
	db.Files[record.ID] = record

	encryptedDB, err := metadata.EncryptMetadata(db, sess.GetMetaKey())
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	_, err = coordinator.UpdateMetadata(context.Background(), &pb.UpdateMetadataRequest{
		EncryptedDb: encryptedDB,
	})
	if err != nil {
		return fmt.Errorf("failed to update metadata on coordinator: %w", err)
	}

	return nil
}

func (c *Client) uploadShard(endpoint, shardID string, data []byte, tlsConfig *tls.Config) error {
	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewStorageNodeClient(conn)
	stream, err := client.PutShard(context.Background())
	if err != nil {
		return err
	}

	// Send in chunks of 64KB
	chunkSize := 64 * 1024
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		err := stream.Send(&pb.ShardChunk{
			ShardId: shardID,
			Data:    data[i:end],
		})
		if err != nil {
			return err
		}
	}

	res, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("storage node reported failure")
	}
	return nil
}

func (c *Client) ListFilesDistributed(coordinatorAddr string, tlsConfig *tls.Config) ([]*types.FileRecord, error) {
	// 1. Ensure session
	sess, err := session.GetSession()
	if err != nil {
		if err := c.ensureSession(); err != nil {
			return nil, err
		}
		sess, _ = session.GetSession()
	}

	// 2. Connect to Coordinator
	conn, err := grpc.Dial(coordinatorAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	coordinator := pb.NewCoordinatorClient(conn)

	// 3. Get Metadata
	resp, err := coordinator.GetMetadata(context.Background(), &pb.GetMetadataRequest{})
	if err != nil {
		return nil, err
	}

	if resp.EncryptedDb == nil {
		return []*types.FileRecord{}, nil
	}

	db, err := metadata.DecryptMetadata(resp.EncryptedDb, sess.GetMetaKey())
	if err != nil {
		return nil, err
	}

	var files []*types.FileRecord
	for _, f := range db.Files {
		files = append(files, f)
	}
	return files, nil
}

func (c *Client) ExportFileDistributed(fileID, destDir string, coordinatorAddr string, tlsConfig *tls.Config) error {
	// 1. Ensure session
	sess, err := session.GetSession()
	if err != nil {
		if err := c.ensureSession(); err != nil {
			return err
		}
		sess, _ = session.GetSession()
	}

	// 2. Connect to Coordinator
	conn, err := grpc.Dial(coordinatorAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()
	coordinator := pb.NewCoordinatorClient(conn)

	// 3. Get Download Plan (which includes shard locations)
	plan, err := coordinator.GetDownloadPlan(context.Background(), &pb.DownloadPlanRequest{FileId: fileID})
	if err != nil {
		return err
	}

	// 4. Get Metadata to find the record
	mResp, err := coordinator.GetMetadata(context.Background(), &pb.GetMetadataRequest{})
	if err != nil || mResp.EncryptedDb == nil {
		return fmt.Errorf("failed to get metadata from coordinator: %v", err)
	}
	db, err := metadata.DecryptMetadata(mResp.EncryptedDb, sess.GetMetaKey())
	if err != nil {
		return fmt.Errorf("failed to decrypt metadata: %v", err)
	}

	var record *types.FileRecord
	for _, f := range db.Files {
		if f.ID == fileID {
			record = f
			break
		}
	}
	if record == nil {
		return fmt.Errorf("file not found in coordinator metadata")
	}

	dest := filepath.Join(destDir, record.Filename)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	masterKey := sess.GetMasterKey()
	limit := make(chan struct{}, 4)

	for _, chunk := range record.Chunks {
		shards := make([][]byte, objects.DataShards+objects.ParityShards)
		var wg sync.WaitGroup
		
		for j, s := range chunk.Shards {
			// Find location for this shard index from plan
			// Actually, the plan map is ShardIndex -> NodeEndpoint
			endpoint := plan.Locations[int32(j)]
			
			wg.Add(1)
			go func(idx int, sID string, addr string) {
				defer wg.Done()
				limit <- struct{}{}
				defer func() { <-limit }()

				data, err := c.downloadShard(addr, sID, tlsConfig)
				if err == nil {
					shards[idx] = data
				}
			}(j, s.ShardID, endpoint)
		}
		wg.Wait()

		plaintext, err := objects.ReconstructAndDecrypt(shards, masterKey, chunk.Size)
		if err != nil {
			return fmt.Errorf("failed to reconstruct chunk: %w", err)
		}
		if _, err := out.Write(plaintext); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) downloadShard(endpoint, shardID string, tlsConfig *tls.Config) ([]byte, error) {
	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := pb.NewStorageNodeClient(conn)
	stream, err := client.GetShard(context.Background(), &pb.ShardRequest{ShardId: shardID})
	if err != nil {
		return nil, err
	}

	var data []byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data = append(data, chunk.Data...)
	}
	return data, nil
}

func (c *Client) ensureSession() error {
	// Re-use logic from daemon.EnsureLocalSession but call it here
	// This might need daemon package imports
	var reply types.KeysReply
	err := c.RPC.Call("VaultDaemon.GetKeys", &struct{}{}, &reply)
	if err != nil {
		return fmt.Errorf("vault is locked or daemon not running: %w", err)
	}

	return session.InitSession(reply.MasterKey, reply.MetaKey)
}
