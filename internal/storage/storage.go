package storage

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"vaultfs/internal/config"
	"vaultfs/internal/crypto"
	"vaultfs/internal/metadata"
	"vaultfs/internal/objects"
	"vaultfs/internal/session"
)

var (
	ErrNotInitialized = errors.New("vault is not initialized")
	ErrAlreadyInit    = errors.New("vault is already initialized")
	ErrInvalidPass    = errors.New("invalid password")
	ErrFileNotFound   = errors.New("file not found")
)

type Vault struct {
	BaseDir string
}

func NewVault(baseDir string) *Vault {
	return &Vault{BaseDir: baseDir}
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
		if os.IsNotExist(err) {
			return ErrNotInitialized
		}
		return err
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

func (v *Vault) AddFile(sourcePath string) error {
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

	record := &metadata.FileRecord{
		ID:       v.generateUUID(),
		Filename: filepath.Base(sourcePath),
		Size:     info.Size(),
		Created:  time.Now().Unix(),
		Modified: info.ModTime().Unix(),
		Chunks:   []string{},
	}

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(v.BaseDir, "objects")

	buf := make([]byte, objects.ChunkSize)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			chunkID, storeErr := objects.StoreChunk(objectsDir, buf[:n], masterKey)
			if storeErr != nil {
				return fmt.Errorf("failed to store chunk: %w", storeErr)
			}
			record.Chunks = append(record.Chunks, chunkID)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
	if err != nil {
		return err
	}

	db.Files[record.ID] = record
	return metadata.SaveEncryptedMetadata(metaPath, db, sess.GetMetaKey())
}

func (v *Vault) ExportFile(fileID string, outPath string) error {
	sess, err := session.GetSession()
	if err != nil {
		return err
	}

	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
	if err != nil {
		return err
	}

	record, ok := db.Files[fileID]
	if !ok {
		return ErrFileNotFound
	}

	// Make sure outPath is a directory, append filename
	dest := filepath.Join(outPath, record.Filename)

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(v.BaseDir, "objects")

	for _, chunkID := range record.Chunks {
		plaintext, err := objects.RetrieveChunk(objectsDir, chunkID, masterKey)
		if err != nil {
			return err
		}
		if _, err := out.Write(plaintext); err != nil {
			return err
		}
	}

	return nil
}

func (v *Vault) ListFiles() ([]*metadata.FileRecord, error) {
	sess, err := session.GetSession()
	if err != nil {
		return nil, err
	}

	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
	if err != nil {
		return nil, err
	}

	var files []*metadata.FileRecord
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

	metaPath := filepath.Join(v.BaseDir, "metadata.enc")
	db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
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
	return metadata.SaveEncryptedMetadata(metaPath, db, sess.GetMetaKey())
}

func (v *Vault) ChangePassword(oldPass, newPass []byte) error {
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
