package daemon

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/config"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

const SocketName = "gocryptvault.sock"
const AutoLockTimeout = 15 * time.Minute

type Daemon struct {
	vault        *storage.Vault
	mu           sync.Mutex
	lastActivity time.Time
}

func NewDaemon(vault *storage.Vault) *Daemon {
	d := &Daemon{
		vault: vault,
	}
	go d.autoLockRoutine()
	return d
}

func (d *Daemon) autoLockRoutine() {
	for {
		time.Sleep(1 * time.Minute)
		d.mu.Lock()
		if session.IsUnlocked() && time.Since(d.lastActivity) > AutoLockTimeout {
			log.Println("Auto-locking vault due to inactivity...")
			session.DestroySession()
		}
		d.mu.Unlock()
	}
}

func (d *Daemon) Unlock(password []byte, reply *bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.vault.Unlock(password)
	if err != nil {
		*reply = false
		return err
	}
	d.lastActivity = time.Now()
	*reply = true
	return nil
}

func (d *Daemon) GetKeys(req *struct{}, reply *types.KeysReply) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	sess, err := session.GetSessionLocal()
	if err != nil {
		return err
	}

	reply.MasterKey = sess.GetMasterKey()
	reply.MetaKey = sess.GetMetaKey()
	d.lastActivity = time.Now()

	return nil
}

func (d *Daemon) GetSalt(req *struct{}, reply *[]byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	cfg, err := config.LoadConfig(filepath.Join(d.vault.BaseDir, "config.enc"))
	if err != nil {
		return err
	}

	*reply = cfg.Salt
	return nil
}

func (d *Daemon) ListFiles(req *struct{}, reply *[]*types.FileRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	files, err := d.vault.ListFiles()
	if err != nil {
		return err
	}

	*reply = files
	d.lastActivity = time.Now()
	return nil
}

func (d *Daemon) GetFile(fileID string, reply *types.FileRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	files, err := d.vault.ListFiles()
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.ID == fileID {
			*reply = *f
			d.lastActivity = time.Now()
			return nil
		}
	}

	return fmt.Errorf("file not found")
}

func (d *Daemon) AddFile(args *types.AddFileArgs, reply *bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.vault.AddFile(args.SourcePath, args.LogicalName)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	d.lastActivity = time.Now()
	return nil
}

func (d *Daemon) ExportFile(args *types.ExportFileArgs, reply *bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.vault.ExportFile(args.FileID, args.DestDir)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	d.lastActivity = time.Now()
	return nil
}

func (d *Daemon) Lock(req *struct{}, reply *bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	session.DestroySession()
	*reply = true
	return nil
}

func (d *Daemon) Status(req *struct{}, reply *types.StatusReply) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	unlocked := session.IsUnlocked()
	reply.Unlocked = unlocked

	if unlocked {
		rem := AutoLockTimeout - time.Since(d.lastActivity)
		if rem < 0 {
			rem = 0
		}
		reply.TimeUntilLock = rem.String()
	} else {
		reply.TimeUntilLock = "0s"
	}

	return nil
}

func RunServer() error {
	vaultPath := config.GetVaultPath()
	socketPath := filepath.Join(vaultPath, SocketName)

	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		return err
	}

	// Remove old socket if exists
	os.Remove(socketPath)

	vault := storage.NewVault(vaultPath)
	d := NewDaemon(vault)

	rpc.RegisterName("VaultDaemon", d)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}
	defer l.Close()
	defer os.Remove(socketPath)

	// Ensure secure permissions
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("chmod error: %w", err)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Println("Shutting down daemon...")
		l.Close()
		session.DestroySession()
		os.Exit(0)
	}()

	log.Printf("Vault daemon listening on %s", socketPath)
	rpc.Accept(l)
	return nil
}

func ConnectRPC() (*rpc.Client, error) {
	socketPath := filepath.Join(config.GetVaultPath(), SocketName)
	return rpc.Dial("unix", socketPath)
}
