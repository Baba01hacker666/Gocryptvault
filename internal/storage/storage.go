package storage

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/config"
	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"github.com/Baba01hacker666/Gocryptvault/internal/objects"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

var (
	ErrNotInitialized = errors.New("vault is not initialized")
	ErrAlreadyInit    = errors.New("vault is already initialized")
	ErrInvalidPass    = errors.New("invalid password")
	ErrFileNotFound   = errors.New("file not found")
)

type Vault struct {
	BaseDir      string
	mu           sync.RWMutex
	metaCache    *metadata.MetadataDB
	cacheModTime time.Time
}

func NewVault(baseDir string) *Vault {
	return &Vault{BaseDir: baseDir}
}

func (v *Vault) getMetadataLocked() (*metadata.MetadataDB, error) {
	sess, err := session.GetSession()
	if err != nil {
		return nil, err
	}

	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	info, err := os.Stat(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			v.metaCache = metadata.NewMetadataDB()
			return v.metaCache, nil
		}
		return nil, err
	}

	if v.metaCache != nil && info.ModTime().Equal(v.cacheModTime) {
		return v.metaCache, nil
	}

	db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
	if err != nil {
		return nil, err
	}

	v.metaCache = db
	v.cacheModTime = info.ModTime()
	return db, nil
}

func (v *Vault) getMetadata() (*metadata.MetadataDB, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.getMetadataLocked()
}

func (v *Vault) Init(password []byte) error {
	configPath := filepath.Join(v.BaseDir, "config.enc")
	if _, err := os.Stat(configPath); err == nil {
		return ErrAlreadyInit
	}

	if err := os.MkdirAll(filepath.Join(v.BaseDir, "objects"), 0700); err != nil {
		return err
	}

	salt, err := crypto.GenerateRandomBytes(crypto.SaltLen)
	if err != nil {
		return err
	}

	// Derive a Key Encryption Key (KEK) from password
	kek := crypto.DeriveKey(password, salt)
	defer wipeSlice(kek) // wipe after use

	// Generate Master Key and Meta Key
	masterKey, err := crypto.GenerateRandomBytes(crypto.KeyLen)
	if err != nil {
		return err
	}
	defer wipeSlice(masterKey)

	metaKey, err := crypto.GenerateRandomBytes(crypto.KeyLen)
	if err != nil {
		return err
	}
	defer wipeSlice(metaKey)

	// Encrypt keys with KEK
	masterKeyEnc, err := crypto.Encrypt(masterKey, kek)
	if err != nil {
		return err
	}

	metaKeyEnc, err := crypto.Encrypt(metaKey, kek)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Version:      1,
		KDF:          "argon2id",
		Cipher:       "xchacha20poly1305",
		Created:      time.Now().Unix(),
		Salt:         salt,
		MasterKeyEnc: masterKeyEnc,
		MetaKeyEnc:   metaKeyEnc,
	}

	if err := config.SaveConfig(configPath, cfg); err != nil {
		return err
	}

	// Initialize empty metadata DB
	db := metadata.NewMetadataDB()
	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	if err := metadata.SaveEncryptedMetadata(metaPath, db, metaKey); err != nil {
		return err
	}

	return nil
}

func (v *Vault) Unlock(password []byte) error {
	configPath := filepath.Join(v.BaseDir, "config.enc")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return ErrNotInitialized
	}

	kek := crypto.DeriveKey(password, cfg.Salt)
	defer wipeSlice(kek)

	masterKey, err := crypto.Decrypt(cfg.MasterKeyEnc, kek)
	if err != nil {
		return ErrInvalidPass
	}
	defer wipeSlice(masterKey)

	metaKey, err := crypto.Decrypt(cfg.MetaKeyEnc, kek)
	if err != nil {
		return ErrInvalidPass
	}
	defer wipeSlice(metaKey)

	return session.InitSession(masterKey, metaKey)
}

func (v *Vault) Lock() {
	session.DestroySession()
}

func (v *Vault) generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (v *Vault) AddFileAsync(sourcePath string, logicalName string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		errChan <- v.AddFile(sourcePath, logicalName)
		close(errChan)
	}()
	return errChan
}

func (v *Vault) AddFile(sourcePath string, logicalName string) error {
	sess, err := session.GetSession()
	if err != nil {
		return err
	}

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
	// Reset file pointer
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek file: %w", err)
	}

	// Determine number of chunks
	numChunks := int((info.Size() + int64(objects.ChunkSize) - 1) / int64(objects.ChunkSize))
	if numChunks == 0 {
		// Handle empty file
		numChunks = 1
	}

	record := &types.FileRecord{
		ID: v.generateUUID(),
		Filename: func() string {
			if logicalName != "" {
				return logicalName
			}
			return filepath.Base(sourcePath)
		}(),
		Size:       info.Size(),
		MimeType:   mimeType,
		Compressed: true, // New chunks have compression headers
		Created:    time.Now().Unix(),
		Modified:   info.ModTime().Unix(),
		Chunks:     make([]types.ChunkInfo, numChunks),
	}

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(v.BaseDir, "objects")

	type chunkJob struct {
		index int
		data  []byte
	}

	type chunkResult struct {
		index    int
		shardIDs []string
		size     int
		err      error
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 4 {
		numWorkers = 4 // Limit concurrency to avoid excessive memory usage
	}

	jobs := make(chan chunkJob, numWorkers)
	results := make(chan chunkResult, numWorkers)

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				shardIDs, size, err := objects.StoreShards(objectsDir, job.data, masterKey)
				results <- chunkResult{
					index:    job.index,
					shardIDs: shardIDs,
					size:     size,
					err:      err,
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var readErr error
	go func() {
		chunkIndex := 0
		for {
			buf := make([]byte, objects.ChunkSize)
			n, err := f.Read(buf)
			if n > 0 {
				jobs <- chunkJob{
					index: chunkIndex,
					data:  buf[:n],
				}
				chunkIndex++
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				readErr = err
				break
			}
		}
		close(jobs)
	}()

	for res := range results {
		if res.err != nil {
			return fmt.Errorf("failed to store shards: %w", res.err)
		}
		shards := make([]types.ShardInfo, len(res.shardIDs))
		for i, shardID := range res.shardIDs {
			shards[i] = types.ShardInfo{
				Index:   i,
				ShardID: shardID,
				NodeID:  "local",
			}
		}
		record.Chunks[res.index] = types.ChunkInfo{
			Index:  res.index,
			Size:   res.size,
			Shards: shards,
		}
	}

	if readErr != nil {
		return readErr
	}

	// Truncate Chunks slice if empty file resulted in 0 actual chunks written
	if info.Size() == 0 {
		record.Chunks = []types.ChunkInfo{}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	db, err := v.getMetadataLocked()
	if err != nil {
		return err
	}

	db.Files[record.ID] = record
	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	if err := metadata.SaveEncryptedMetadata(metaPath, db, sess.GetMetaKey()); err != nil {
		return err
	}

	// Update cache mod time
	if metaInfo, err := os.Stat(metaPath); err == nil {
		v.cacheModTime = metaInfo.ModTime()
	}

	return nil
}

func (v *Vault) ExportFile(fileID string, outPath string) error {
	sess, err := session.GetSession()
	if err != nil {
		return err
	}

	v.mu.Lock()
	db, err := v.getMetadataLocked()
	if err != nil {
		v.mu.Unlock()
		return err
	}

	record, ok := db.Files[fileID]
	v.mu.Unlock()
	if !ok {
		return ErrFileNotFound
	}

	// FIXED CRIT-02: sanitize the filename from metadata to prevent path traversal.
	// Use only the base name — never allow directory components from stored metadata.
	safeFilename := filepath.Base(record.Filename)
	if safeFilename == "." || safeFilename == "" {
		safeFilename = "exported_file"
	}

	// Resolve the absolute output directory and verify the final path stays inside it.
	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return err
	}
	dest := filepath.Join(absOut, safeFilename)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if len(absDest) <= len(absOut) || absDest[:len(absOut)+1] != absOut+string(filepath.Separator) {
		return fmt.Errorf("export path traversal detected: %q escapes output directory", record.Filename)
	}

	// FIXED HIGH-09: use 0700 for output directory, 0600 for the output file.
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}

	// Write to a temp file first; rename atomically on success so a partial
	// plaintext file is never left on disk if decryption fails mid-way.
	tmpDest := dest + ".tmp"
	out, err := os.OpenFile(tmpDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	// Ensure temp file is cleaned up on any failure path.
	var exportErr error
	defer func() {
		out.Close()
		if exportErr != nil {
			os.Remove(tmpDest)
		}
	}()

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(v.BaseDir, "objects")

	type exportResult struct {
		data []byte
		err  error
	}

	type exportJob struct {
		index     int
		shardIDs  []string
		chunkSize int
		resCh     chan exportResult
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 4 {
		numWorkers = 4
	}

	jobs := make(chan exportJob, numWorkers)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				plaintext, err := objects.RetrieveShards(objectsDir, job.shardIDs, masterKey, job.chunkSize)
				job.resCh <- exportResult{
					data: plaintext,
					err:  err,
				}
			}
		}()
	}

	go func() {
		wg.Wait()
	}()

	futures := make([]chan exportResult, len(record.Chunks))
	for i := range record.Chunks {
		futures[i] = make(chan exportResult, 1)
	}

	maxInFlight := numWorkers * 2
	sem := make(chan struct{}, maxInFlight)

	go func() {
		for i, chunk := range record.Chunks {
			shardIDs := make([]string, len(chunk.Shards))
			for j, s := range chunk.Shards {
				shardIDs[j] = s.ShardID
			}
			sem <- struct{}{} // acquire slot
			jobs <- exportJob{
				index:     i,
				shardIDs:  shardIDs,
				chunkSize: chunk.Size,
				resCh:     futures[i],
			}
		}
		close(jobs)
	}()

	for i := range record.Chunks {
		res := <-futures[i]
		<-sem // release slot
		if res.err != nil {
			exportErr = res.err
			return exportErr
		}
		if _, err := out.Write(res.data); err != nil {
			exportErr = err
			return exportErr
		}
	}

	out.Close() // Close before rename for Windows compatibility
	if err := os.Rename(tmpDest, dest); err != nil {
		exportErr = err
		return exportErr
	}

	return nil
}

func (v *Vault) ListFiles() ([]*types.FileRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	db, err := v.getMetadataLocked()
	if err != nil {
		return nil, err
	}

	var files []*types.FileRecord
	for _, f := range db.Files {
		files = append(files, f)
	}

	return files, nil
}

func (v *Vault) GetFile(fileID string) (*types.FileRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	db, err := v.getMetadataLocked()
	if err != nil {
		return nil, err
	}

	record, ok := db.Files[fileID]
	if !ok {
		return nil, ErrFileNotFound
	}

	return record, nil
}

func (v *Vault) DeleteFile(fileID string) error {
	sess, err := session.GetSession()
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	db, err := v.getMetadataLocked()
	if err != nil {
		return err
	}

	record, ok := db.Files[fileID]
	if !ok {
		return ErrFileNotFound
	}

	objectsDir := filepath.Join(v.BaseDir, "objects")
	for _, chunk := range record.Chunks {
		for _, shard := range chunk.Shards {
			_ = objects.DeleteChunk(objectsDir, shard.ShardID)
		}
	}

	delete(db.Files, fileID)
	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	if err := metadata.SaveEncryptedMetadata(metaPath, db, sess.GetMetaKey()); err != nil {
		return err
	}

	// Update cache mod time
	if info, err := os.Stat(metaPath); err == nil {
		v.cacheModTime = info.ModTime()
	}

	return nil
}

func (v *Vault) ChangePassword(oldPass, newPass []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	configPath := filepath.Join(v.BaseDir, "config.enc")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	oldKek := crypto.DeriveKey(oldPass, cfg.Salt)
	defer wipeSlice(oldKek)

	masterKey, err := crypto.Decrypt(cfg.MasterKeyEnc, oldKek)
	if err != nil {
		return ErrInvalidPass
	}
	defer wipeSlice(masterKey)

	metaKey, err := crypto.Decrypt(cfg.MetaKeyEnc, oldKek)
	if err != nil {
		return ErrInvalidPass
	}
	defer wipeSlice(metaKey)

	// Generate new salt
	newSalt, err := crypto.GenerateRandomBytes(crypto.SaltLen)
	if err != nil {
		return err
	}

	newKek := crypto.DeriveKey(newPass, newSalt)
	defer wipeSlice(newKek)

	newMasterKeyEnc, err := crypto.Encrypt(masterKey, newKek)
	if err != nil {
		return err
	}

	newMetaKeyEnc, err := crypto.Encrypt(metaKey, newKek)
	if err != nil {
		return err
	}

	cfg.Salt = newSalt
	cfg.MasterKeyEnc = newMasterKeyEnc
	cfg.MetaKeyEnc = newMetaKeyEnc

	return config.SaveConfig(configPath, cfg)
}

func wipeSlice(b []byte) {
	if len(b) == 0 {
		return
	}
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}
