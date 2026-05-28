package fuse

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"github.com/Baba01hacker666/Gocryptvault/internal/objects"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
)

type VaultRoot struct {
	fs.Inode
	Vault *storage.Vault
}

var _ = (fs.NodeOnAdder)((*VaultRoot)(nil))
var _ = (fs.NodeReaddirer)((*VaultRoot)(nil))
var _ = (fs.NodeLookuper)((*VaultRoot)(nil))

func (r *VaultRoot) OnAdd(ctx context.Context) {
}

func (r *VaultRoot) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	files, err := r.Vault.ListFiles()
	if err != nil {
		return nil, syscall.ENOENT
	}

	for _, f := range files {
		if f.Filename == name {
			child := &FileNode{
				Vault:    r.Vault,
				RecordID: f.ID,
			}
			return r.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG | 0444}), 0
		}
	}

	return nil, syscall.ENOENT
}

func (r *VaultRoot) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	files, err := r.Vault.ListFiles()
	if err != nil {
		return nil, syscall.EIO
	}

	entries := make([]fuse.DirEntry, 0, len(files))
	for _, f := range files {
		entries = append(entries, fuse.DirEntry{
			Mode: fuse.S_IFREG | 0444,
			Name: f.Filename,
		})
	}
	return fs.NewListDirStream(entries), 0
}

type FileNode struct {
	fs.Inode
	Vault    *storage.Vault
	RecordID string
}

var _ = (fs.NodeOpener)((*FileNode)(nil))
var _ = (fs.NodeGetattrer)((*FileNode)(nil))

func (f *FileNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	files, err := f.Vault.ListFiles()
	if err != nil {
		return syscall.EIO
	}
	for _, record := range files {
		if record.ID == f.RecordID {
			out.Mode = fuse.S_IFREG | 0444
			out.Size = uint64(record.Size)
			return 0
		}
	}
	return syscall.ENOENT
}

func (f *FileNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	return &FileHandle{
		Vault:    f.Vault,
		RecordID: f.RecordID,
	}, fuse.FOPEN_KEEP_CACHE, 0
}

type FileHandle struct {
	Vault    *storage.Vault
	RecordID string
}

var _ = (fs.FileReader)((*FileHandle)(nil))

func (fh *FileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	sess, err := session.GetSession()
	if err != nil {
		return nil, syscall.EIO
	}

	files, err := fh.Vault.ListFiles()
	if err != nil {
		return nil, syscall.EIO
	}

	var record *metadata.FileRecord
	for _, r := range files {
		if r.ID == fh.RecordID {
			record = r
			break
		}
	}
	if record == nil {
		return nil, syscall.ENOENT
	}

	if off >= record.Size {
		return fuse.ReadResultData(nil), 0 // EOF
	}

	readEnd := off + int64(len(dest))
	if readEnd > record.Size {
		readEnd = record.Size
	}

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(fh.Vault.BaseDir, "objects")

	var data []byte

	startChunkIdx := off / objects.ChunkSize
	endChunkIdx := (readEnd - 1) / objects.ChunkSize

	for i := startChunkIdx; i <= endChunkIdx; i++ {
		if i >= int64(len(record.Chunks)) {
			break
		}
		chunkID := record.Chunks[i]
		plaintext, err := objects.RetrieveChunk(objectsDir, chunkID, masterKey, record.Compressed)
		if err != nil {
			return nil, syscall.EIO
		}
		data = append(data, plaintext...)
	}

	offsetWithinChunks := off % objects.ChunkSize
	readSize := readEnd - off

	if offsetWithinChunks+readSize > int64(len(data)) {
		return nil, syscall.EIO
	}

	return fuse.ReadResultData(data[offsetWithinChunks : offsetWithinChunks+readSize]), 0
}

var unmountFunc func() error

func Mount(mountpoint string, vault *storage.Vault) error {
	sess, err := session.GetSession()
	if err != nil || sess == nil {
		return fmt.Errorf("vault must be unlocked to mount")
	}

	root := &VaultRoot{
		Vault: vault,
	}

	server, err := fs.Mount(mountpoint, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName: "vaultfs",
			Name:   "vaultfs",
		},
	})
	if err != nil {
		return err
	}

	log.Printf("Mounted vault at %s", mountpoint)

	unmountFunc = server.Unmount

	go server.Wait()

	return nil
}

func Unmount(mountpoint string) error {
    if unmountFunc != nil {
        return unmountFunc()
    }
    // Fallback if we didn't start the mount process in this instance
    return fmt.Errorf("unmount not supported directly without mount server reference, use umount %s", mountpoint)
}
