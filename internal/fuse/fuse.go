package fuse

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"github.com/Baba01hacker666/Gocryptvault/internal/objects"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
)

type VaultFS struct {
	Vault *storage.Vault
}

func (vfs *VaultFS) Root() (fs.Node, error) {
	return &Dir{Vault: vfs.Vault}, nil
}

type Dir struct {
	Vault *storage.Vault
}

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0555
	return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	files, err := d.Vault.ListFiles()
	if err != nil {
		return nil, fuse.ENOENT
	}

	for _, f := range files {
		if f.Filename == name {
			return &File{Vault: d.Vault, RecordID: f.ID}, nil
		}
	}

	return nil, fuse.ENOENT
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	files, err := d.Vault.ListFiles()
	if err != nil {
		return nil, err
	}

	var dirents []fuse.Dirent
	for _, f := range files {
		dirents = append(dirents, fuse.Dirent{
			Inode: 0,
			Name:  f.Filename,
			Type:  fuse.DT_File,
		})
	}
	return dirents, nil
}

type File struct {
	Vault    *storage.Vault
	RecordID string
}

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	files, err := f.Vault.ListFiles()
	if err != nil {
		return err
	}
	for _, record := range files {
		if record.ID == f.RecordID {
			a.Inode = 0
			a.Mode = 0444
			a.Size = uint64(record.Size)
			return nil
		}
	}
	return fuse.ENOENT
}

func (f *File) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	sess, err := session.GetSession()
	if err != nil {
		return fuse.EIO
	}

	files, err := f.Vault.ListFiles()
	if err != nil {
		return fuse.EIO
	}

	var record *metadata.FileRecord
	for _, r := range files {
		if r.ID == f.RecordID {
			record = r
			break
		}
	}
	if record == nil {
		return fuse.ENOENT
	}

	if req.Offset >= record.Size {
		return nil // EOF
	}

	readEnd := req.Offset + int64(req.Size)
	if readEnd > record.Size {
		readEnd = record.Size
	}

	masterKey := sess.GetMasterKey()
	objectsDir := filepath.Join(f.Vault.BaseDir, "objects")

	var data []byte

	startChunkIdx := req.Offset / objects.ChunkSize
	endChunkIdx := (readEnd - 1) / objects.ChunkSize

	for i := startChunkIdx; i <= endChunkIdx; i++ {
		if i >= int64(len(record.Chunks)) {
			break
		}
		chunkID := record.Chunks[i]
		plaintext, err := objects.RetrieveChunk(objectsDir, chunkID, masterKey, record.Compressed)
		if err != nil {
			return fuse.EIO
		}
		data = append(data, plaintext...)
	}

	offsetWithinChunks := req.Offset % objects.ChunkSize
	readSize := readEnd - req.Offset

	if offsetWithinChunks+readSize > int64(len(data)) {
		return fuse.EIO
	}

	resp.Data = data[offsetWithinChunks : offsetWithinChunks+readSize]
	return nil
}

func Mount(mountpoint string, vault *storage.Vault) error {
	sess, err := session.GetSession()
	if err != nil || sess == nil {
		return fmt.Errorf("vault must be unlocked to mount")
	}

	c, err := fuse.Mount(
		mountpoint,
		fuse.FSName("vaultfs"),
		fuse.Subtype("vaultfs"),
	)
	if err != nil {
		return err
	}
	defer c.Close()

	log.Printf("Mounted vault at %s", mountpoint)

	err = fs.Serve(c, &VaultFS{Vault: vault})
	if err != nil {
		return err
	}

	return nil
}

func Unmount(mountpoint string) error {
	return fuse.Unmount(mountpoint)
}
