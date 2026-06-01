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
		Chunks:     make([]string, numChunks),
	}

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(v.BaseDir, "objects")

	type chunkJob struct {
		index int
		data  []byte
	}

	type chunkResult struct {
		index   int
		chunkID string
		err     error
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
				chunkID, err := objects.StoreChunk(objectsDir, job.data, masterKey)
				results <- chunkResult{
					index:   job.index,
					chunkID: chunkID,
					err:     err,
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
			return fmt.Errorf("failed to store chunk: %w", res.err)
		}
		record.Chunks[res.index] = res.chunkID
	}

	if readErr != nil {
		return readErr
	}

	// Truncate Chunks slice if empty file resulted in 0 actual chunks written
	if info.Size() == 0 {
		record.Chunks = []string{}
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

	// Make sure outPath is a directory, append filename
	dest := filepath.Join(outPath, record.Filename)

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(v.BaseDir, "objects")

	type exportJob struct {
		index   int
		chunkID string
	}

	type exportResult struct {
		index int
		data  []byte
		err   error
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 4 {
		numWorkers = 4
	}

	jobs := make(chan exportJob, numWorkers)
	results := make(chan exportResult, numWorkers)

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				plaintext, err := objects.RetrieveChunk(objectsDir, job.chunkID, masterKey, record.Compressed)
				results <- exportResult{
					index: job.index,
					data:  plaintext,
					err:   err,
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		for i, chunkID := range record.Chunks {
			jobs <- exportJob{
				index:   i,
				chunkID: chunkID,
			}
		}
		close(jobs)
	}()

	// Process results incrementally to avoid loading entire file in memory
	resultMap := make(map[int][]byte)
	nextIndexToWrite := 0

	for res := range results {
		if res.err != nil {
			return res.err
		}
		resultMap[res.index] = res.data

		// Drain the map sequentially
		for {
			if data, ok := resultMap[nextIndexToWrite]; ok {
				if _, err := out.Write(data); err != nil {
					return err
				}
				delete(resultMap, nextIndexToWrite)
				nextIndexToWrite++
			} else {
				break
			}
		}
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
	for _, chunkID := range record.Chunks {
		_ = objects.DeleteChunk(objectsDir, chunkID)
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
