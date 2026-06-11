package daemon

import (
	"context"
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
	quit         chan struct{} // FIXED HIGH-04: goroutine now has a shutdown path
}

func NewDaemon(vault *storage.Vault) *Daemon {
	d := &Daemon{
		vault: vault,
		quit:  make(chan struct{}),
	}
	go d.autoLockRoutine()
	return d
}

// Stop signals the autoLockRoutine to exit cleanly.
func (d *Daemon) Stop() {
	close(d.quit)
}

// FIXED HIGH-04: autoLockRoutine now exits cleanly via quit channel.
// FIXED MED-09: session lock is NOT held inside d.mu to avoid lock-order deadlock.
func (d *Daemon) autoLockRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-d.quit:
			return
		case <-ticker.C:
			// Read lastActivity under d.mu, then release before touching session
			d.mu.Lock()
			elapsed := time.Since(d.lastActivity)
			d.mu.Unlock()

			// session has its own internal lock; do NOT hold d.mu here
			if session.IsUnlocked() && elapsed > AutoLockTimeout {
				log.Println("Auto-locking vault due to inactivity...")
				session.DestroySession()
			}
		}
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

// FIXED CRIT-01: GetKeys is REMOVED. Raw key material must never leave the daemon.
// All vault operations are performed by the daemon on behalf of clients; results
// (decrypted file content, listings) are returned — never the keys themselves.

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

	// Ensure secure permissions on the socket file
	if err := os.Chmod(socketPath, 0600); err != nil {
		l.Close()
		os.Remove(socketPath)
		return fmt.Errorf("chmod error: %w", err)
	}

	// FIXED LOW-02: use context cancel instead of os.Exit so defers run correctly.
	ctx, cancel := context.WithCancel(context.Background())
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Println("Shutting down daemon...")
		cancel()
		d.Stop()
		l.Close()
		session.DestroySession()
		os.Remove(socketPath)
	}()

	log.Printf("Vault daemon listening on %s", socketPath)
	go rpc.Accept(l)

	<-ctx.Done()
	return nil
}

func ConnectRPC() (*rpc.Client, error) {
	socketPath := filepath.Join(config.GetVaultPath(), SocketName)
	return rpc.Dial("unix", socketPath)
}
