package fuse

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Baba01hacker666/Gocryptvault/internal/objects"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type DirNode struct {
	fs.Inode
	Vault *storage.Vault
	Path  string
}

var _ = (fs.NodeOnAdder)((*DirNode)(nil))
var _ = (fs.NodeReaddirer)((*DirNode)(nil))
var _ = (fs.NodeLookuper)((*DirNode)(nil))

func (d *DirNode) OnAdd(ctx context.Context) {}

func (d *DirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	files, err := d.Vault.ListFiles()
	if err != nil {
		return nil, syscall.ENOENT
	}

	searchPrefix := ""
	if d.Path != "" {
		searchPrefix = d.Path + string(filepath.Separator)
	}

	for _, f := range files {
		if !strings.HasPrefix(f.Filename, searchPrefix) {
			continue
		}

		relPath := strings.TrimPrefix(f.Filename, searchPrefix)
		parts := strings.Split(relPath, string(filepath.Separator))

		if parts[0] == name {
			if len(parts) == 1 {
				// It's a file
				child := &FileNode{
					Vault:    d.Vault,
					RecordID: f.ID,
				}
				return d.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG | 0444}), 0
			} else {
				// It's a directory
				childDir := &DirNode{
					Vault: d.Vault,
					Path:  filepath.Join(d.Path, name),
				}
				return d.NewInode(ctx, childDir, fs.StableAttr{Mode: fuse.S_IFDIR | 0555}), 0
			}
		}
	}

	return nil, syscall.ENOENT
}

func (d *DirNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	files, err := d.Vault.ListFiles()
	if err != nil {
		return nil, syscall.EIO
	}

	searchPrefix := ""
	if d.Path != "" {
		searchPrefix = d.Path + string(filepath.Separator)
	}

	entriesMap := make(map[string]fuse.DirEntry)

	for _, f := range files {
		if !strings.HasPrefix(f.Filename, searchPrefix) {
			continue
		}

		relPath := strings.TrimPrefix(f.Filename, searchPrefix)
		parts := strings.Split(relPath, string(filepath.Separator))

		if len(parts) == 1 {
			// File
			entriesMap[parts[0]] = fuse.DirEntry{
				Mode: fuse.S_IFREG | 0444,
				Name: parts[0],
			}
		} else {
			// Directory
			entriesMap[parts[0]] = fuse.DirEntry{
				Mode: fuse.S_IFDIR | 0555,
				Name: parts[0],
			}
		}
	}

	entries := make([]fuse.DirEntry, 0, len(entriesMap))
	for _, e := range entriesMap {
		entries = append(entries, e)
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
	record, err := f.Vault.GetFile(f.RecordID)
	if err != nil {
		if err == storage.ErrFileNotFound {
			return syscall.ENOENT
		}
		return syscall.EIO
	}
	out.Mode = fuse.S_IFREG | 0444
	out.Size = uint64(record.Size)
	return 0
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

	record, err := fh.Vault.GetFile(fh.RecordID)
	if err != nil {
		if err == storage.ErrFileNotFound {
			return nil, syscall.ENOENT
		}
		return nil, syscall.EIO
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
		chunk := record.Chunks[i]
		shardIDs := make([]string, len(chunk.Shards))
		for j, s := range chunk.Shards {
			shardIDs[j] = s.ShardID
		}
		plaintext, err := objects.RetrieveShards(objectsDir, shardIDs, masterKey, chunk.Size)
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

	root := &DirNode{
		Vault: vault,
		Path:  "",
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
