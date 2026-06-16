package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/Baba01hacker666/Gocryptvault/api/proto/v1"
	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"github.com/Baba01hacker666/Gocryptvault/internal/objects"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (c *Client) AddFileDistributed(sourcePath, logicalName string, coordinatorAddr string, tlsConfig *tls.Config, hidden bool, hiddenPassword string) error {
	// 1. Ensure we have keys (session)
	sess, err := session.GetSession()
	if err != nil {
		// Try to get from daemon
		if err := c.ensureSession(); err != nil {
			return err
		}
		sess, _ = session.GetSession()
	}

	var metaKey []byte
	var offset int
	if hidden {
		salt, err := c.GetSalt()
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		metaKey = crypto.DeriveHiddenKey([]byte(hiddenPassword), salt)
		offset = crypto.DeriveHiddenOffset([]byte(hiddenPassword), salt)
	} else {
		metaKey = sess.GetMetaKey()
		offset = 0
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
	shardLocs := &pb.ShardLocations{
		ShardToNode: make(map[string]string),
	}

	// Track successfully uploaded shards for cleanup on failure
	uploadedShards := make(map[string]string) // shardID -> endpoint
	var uploadMu sync.Mutex

	cleanup := func() {
		for sID, endpoint := range uploadedShards {
			_ = c.deleteShard(endpoint, sID, tlsConfig)
		}
	}

	for i := 0; i < numChunks; i++ {
		buf := make([]byte, objects.ChunkSize)
		n, err := f.Read(buf)
		if n == 0 && err == io.EOF && i > 0 { break }
		if err != nil && err != io.EOF {
			cleanup()
			return err
		}

		data := buf[:n]
		
		// Get upload plan for this chunk's shards
		// objects.DataShards + objects.ParityShards = 6
		planReq := &pb.UploadPlanRequest{ShardCount: int32(objects.DataShards + objects.ParityShards)}
		plan, err := coordinator.GetUploadPlan(context.Background(), planReq)
		if err != nil {
			cleanup()
			return fmt.Errorf("failed to get upload plan: %w", err)
		}

		shards, ciphertextSize, err := objects.EncryptAndShard(data, masterKey)
		if err != nil {
			cleanup()
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
			
			uploadMu.Lock()
			shardLocs.ShardToNode[shardID] = nodeEndpoint
			uploadMu.Unlock()

			wg.Add(1)
			go func(idx int, sData []byte, sID string, endpoint string) {
				defer wg.Done()
				limit <- struct{}{}
				defer func() { <-limit }()

				if err := c.uploadShard(endpoint, sID, sData, tlsConfig); err != nil {
					shardErrors <- fmt.Errorf("shard %d upload failed: %w", idx, err)
				} else {
					uploadMu.Lock()
					uploadedShards[sID] = endpoint
					uploadMu.Unlock()
				}
			}(j, shard, shardID, nodeEndpoint)
		}

		wg.Wait()
		close(shardErrors)
		for err := range shardErrors {
			if err != nil {
				cleanup()
				return err
			}
		}

		record.Chunks[i] = chunkInfo
	}

	// 5. Update Metadata
	resp, err := coordinator.GetMetadata(context.Background(), &pb.GetMetadataRequest{})
	var db *metadata.MetadataDB
	var blob []byte

	if err == nil && resp != nil && resp.EncryptedDb != nil {
		blob = resp.EncryptedDb
		var encryptedData []byte
		var extErr error
		if hidden {
			encryptedData, extErr = metadata.ExtractHidden(blob, offset)
		} else {
			encryptedData, extErr = metadata.ExtractDecoy(blob)
		}
		if extErr == nil {
			db, err = metadata.DecryptMetadata(encryptedData, metaKey)
			if err != nil {
				db = metadata.NewMetadataDB()
			}
		} else {
			db = metadata.NewMetadataDB()
		}
	} else {
		db = metadata.NewMetadataDB()
	}
	db.Files[record.ID] = record

	var encryptedDB []byte
	if hidden {
		encryptedDB, err = metadata.EncryptMetadataDeniable(db, metaKey, metadata.HiddenBlobSize)
	} else {
		encryptedDB, err = metadata.EncryptMetadataDeniable(db, metaKey, metadata.DecoyBlobSize)
	}
	if err != nil {
		cleanup()
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	newBlob := make([]byte, metadata.MetadataBlobSize)
	if len(blob) == metadata.MetadataBlobSize {
		copy(newBlob, blob)
	} else {
		_, _ = rand.Read(newBlob)
	}

	if hidden {
		if offset+len(encryptedDB) > metadata.MetadataBlobSize {
			cleanup()
			return fmt.Errorf("hidden metadata too large")
		}
		copy(newBlob[offset:], encryptedDB)
	} else {
		if len(encryptedDB) > metadata.MetadataBlobSize {
			cleanup()
			return fmt.Errorf("decoy metadata too large")
		}
		copy(newBlob[0:], encryptedDB)
	}

	_, err = coordinator.UpdateMetadata(context.Background(), &pb.UpdateMetadataRequest{
		EncryptedDb: newBlob,
		NewFileLocations: map[string]*pb.ShardLocations{
			record.ID: shardLocs,
		},
	})
	if err != nil {
		cleanup()
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

func (c *Client) ListFilesDistributed(coordinatorAddr string, tlsConfig *tls.Config, hidden bool, hiddenPassword string) ([]*types.FileRecord, error) {
	// 1. Ensure session
	sess, err := session.GetSession()
	if err != nil {
		if err := c.ensureSession(); err != nil {
			return nil, err
		}
		sess, _ = session.GetSession()
	}

	var metaKey []byte
	var offset int
	if hidden {
		salt, err := c.GetSalt()
		if err != nil {
			return nil, fmt.Errorf("failed to get salt: %w", err)
		}
		metaKey = crypto.DeriveHiddenKey([]byte(hiddenPassword), salt)
		offset = crypto.DeriveHiddenOffset([]byte(hiddenPassword), salt)
	} else {
		metaKey = sess.GetMetaKey()
		offset = 0
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

	var encryptedData []byte
	if hidden {
		encryptedData, err = metadata.ExtractHidden(resp.EncryptedDb, offset)
	} else {
		encryptedData, err = metadata.ExtractDecoy(resp.EncryptedDb)
	}
	if err != nil {
		return nil, err
	}

	db, err := metadata.DecryptMetadata(encryptedData, metaKey)
	if err != nil {
		return nil, err
	}

	var files []*types.FileRecord
	for _, f := range db.Files {
		files = append(files, f)
	}
	return files, nil
}

func (c *Client) ExportFileDistributed(fileID, destDir string, coordinatorAddr string, tlsConfig *tls.Config, hidden bool, hiddenPassword string) error {
	// 1. Ensure session
	sess, err := session.GetSession()
	if err != nil {
		if err := c.ensureSession(); err != nil {
			return err
		}
		sess, _ = session.GetSession()
	}

	var metaKey []byte
	var offset int
	if hidden {
		salt, err := c.GetSalt()
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		metaKey = crypto.DeriveHiddenKey([]byte(hiddenPassword), salt)
		offset = crypto.DeriveHiddenOffset([]byte(hiddenPassword), salt)
	} else {
		metaKey = sess.GetMetaKey()
		offset = 0
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

	var encryptedData []byte
	if hidden {
		encryptedData, err = metadata.ExtractHidden(mResp.EncryptedDb, offset)
	} else {
		encryptedData, err = metadata.ExtractDecoy(mResp.EncryptedDb)
	}
	if err != nil {
		return err
	}

	db, err := metadata.DecryptMetadata(encryptedData, metaKey)
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
		var shardMu sync.Mutex
		foundCount := 0
		
		for _, s := range chunk.Shards {
			// Find location for this shard ID from plan
			endpoint, ok := plan.Locations[s.ShardID]
			if !ok || endpoint == "" {
				continue
			}
			
			wg.Add(1)
			go func(idx int, sID string, addr string) {
				defer wg.Done()
				limit <- struct{}{}
				defer func() { <-limit }()

				data, err := c.downloadShard(addr, sID, tlsConfig)
				if err == nil {
					shardMu.Lock()
					shards[idx] = data
					foundCount++
					shardMu.Unlock()
				}
			}(s.Index, s.ShardID, endpoint)
		}
		wg.Wait()

		if foundCount < objects.DataShards {
			return fmt.Errorf("insufficient shards for chunk (found %d, need %d)", foundCount, objects.DataShards)
		}

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

func (c *Client) DeleteFileDistributed(fileID string, coordinatorAddr string, tlsConfig *tls.Config, hidden bool, hiddenPassword string) error {
	// 1. Ensure session
	sess, err := session.GetSession()
	if err != nil {
		if err := c.ensureSession(); err != nil {
			return err
		}
		sess, _ = session.GetSession()
	}

	var metaKey []byte
	var offset int
	if hidden {
		salt, err := c.GetSalt()
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		metaKey = crypto.DeriveHiddenKey([]byte(hiddenPassword), salt)
		offset = crypto.DeriveHiddenOffset([]byte(hiddenPassword), salt)
	} else {
		metaKey = sess.GetMetaKey()
		offset = 0
	}

	// 2. Connect to Coordinator
	conn, err := grpc.Dial(coordinatorAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()
	coordinator := pb.NewCoordinatorClient(conn)

	// 3. Get Download Plan to find shard locations
	plan, err := coordinator.GetDownloadPlan(context.Background(), &pb.DownloadPlanRequest{FileId: fileID})
	if err != nil {
		return err
	}

	// 4. Delete shards from nodes
	limit := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for sID, endpoint := range plan.Locations {
		wg.Add(1)
		go func(id string, addr string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()

			_ = c.deleteShard(addr, id, tlsConfig) // Ignore individual shard deletion errors for now
		}(sID, endpoint)
	}
	wg.Wait()

	// 5. Update Metadata (remove file record from metadata.enc)
	mResp, err := coordinator.GetMetadata(context.Background(), &pb.GetMetadataRequest{})
	if err != nil {
		return fmt.Errorf("failed to get metadata from coordinator: %w", err)
	}
	if mResp.EncryptedDb != nil {
		blob := mResp.EncryptedDb
		var encryptedData []byte
		var extErr error
		if hidden {
			encryptedData, extErr = metadata.ExtractHidden(blob, offset)
		} else {
			encryptedData, extErr = metadata.ExtractDecoy(blob)
		}

		if extErr == nil {
			db, err := metadata.DecryptMetadata(encryptedData, metaKey)
			if err == nil {
				if _, exists := db.Files[fileID]; exists {
					delete(db.Files, fileID)
					var encryptedDB []byte
					if hidden {
						encryptedDB, err = metadata.EncryptMetadataDeniable(db, metaKey, metadata.HiddenBlobSize)
					} else {
						encryptedDB, err = metadata.EncryptMetadataDeniable(db, metaKey, metadata.DecoyBlobSize)
					}
					if err == nil {
						newBlob := make([]byte, metadata.MetadataBlobSize)
						if len(blob) == metadata.MetadataBlobSize {
							copy(newBlob, blob)
						} else {
							_, _ = rand.Read(newBlob)
						}

						if hidden {
							if offset+len(encryptedDB) <= metadata.MetadataBlobSize {
								copy(newBlob[offset:], encryptedDB)
							}
						} else {
							if len(encryptedDB) <= metadata.MetadataBlobSize {
								copy(newBlob[0:], encryptedDB)
							}
						}

						_, _ = coordinator.UpdateMetadata(context.Background(), &pb.UpdateMetadataRequest{
							EncryptedDb: newBlob,
						})
					}
				}
			}
		}
	}

	// 6. Call Coordinator.DeleteMetadata to remove persistent tracking state
	_, err = coordinator.DeleteMetadata(context.Background(), &pb.DeleteMetadataRequest{FileId: fileID})
	if err != nil {
		return fmt.Errorf("failed to delete tracking metadata: %w", err)
	}
	return nil
}

func (c *Client) deleteShard(endpoint, shardID string, tlsConfig *tls.Config) error {
	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewStorageNodeClient(conn)
	res, err := client.DeleteShard(context.Background(), &pb.ShardRequest{ShardId: shardID})
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("storage node reported failure")
	}
	return nil
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

type NodeStatus struct {
	ID            string `json:"ID"`
	Endpoint      string `json:"Endpoint"`
	CapacityBytes int64  `json:"CapacityBytes"`
	LastSeen      string `json:"LastSeen"`
}

func (c *Client) GetClusterStatus(coordinatorAddr string, tlsConfig *tls.Config) ([]NodeStatus, error) {
	// Use HTTPS to contact the REST endpoint of the coordinator
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	url := fmt.Sprintf("https://%s/api/v1/cluster/status", coordinatorAddr)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to contact coordinator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("coordinator returned status %d", resp.StatusCode)
	}

	var result struct {
		Status string       `json:"status"`
		Nodes  []NodeStatus `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Nodes, nil
}
