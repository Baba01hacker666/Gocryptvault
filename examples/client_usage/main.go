package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
)

func main() {
	// 1. Create a new client to talk to the daemon
	c, err := client.NewClient()
	if err != nil {
		log.Fatalf("Is the vault daemon running? Error: %v", err)
	}
	defer c.Close()

	// 2. Check if unlocked
	unlocked, err := c.IsUnlocked()
	if err != nil {
		log.Fatal(err)
	}
	if !unlocked {
		fmt.Println("Vault is locked. Unlocking with 'password'...")
		if _, err := c.Unlock([]byte("password")); err != nil {
			log.Fatal(err)
		}
	}

	// 3. Add a file
	tmpFile := filepath.Join(os.TempDir(), "lib_example.txt")
	os.WriteFile(tmpFile, []byte("Content from library example"), 0644)
	defer os.Remove(tmpFile)

	fmt.Println("Adding file to vault...")
	if err := c.AddFile(tmpFile, "example.txt"); err != nil {
		log.Fatal(err)
	}

	// 4. List files
	fmt.Println("Listing files:")
	files, err := c.ListFiles()
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		fmt.Printf("- %s (ID: %s, Size: %d)\n", f.Filename, f.ID, f.Size)
	}

	// 5. Export a file
	if len(files) > 0 {
		exportDir := "./exported_files"
		os.Mkdir(exportDir, 0755)
		fmt.Printf("Exporting %s to %s...\n", files[0].Filename, exportDir)
		if err := c.ExportFile(files[0].ID, exportDir); err != nil {
			log.Fatal(err)
		}
	}
}
