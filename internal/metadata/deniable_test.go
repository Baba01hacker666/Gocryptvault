package metadata

import (
	"bytes"
	"testing"

	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

func TestDeniablePackaging(t *testing.T) {
	decoy := []byte("decoy metadata")
	hidden := []byte("hidden metadata")
	offset := 512 * 1024 // 512KB

	// Constants should be available in the package
	blob, err := PackageDeniable(decoy, hidden, offset)
	if err != nil {
		t.Fatalf("PackageDeniable failed: %v", err)
	}

	if len(blob) != MetadataBlobSize {
		t.Errorf("expected size %d, got %d", MetadataBlobSize, len(blob))
	}

	extractedDecoy, err := ExtractDecoy(blob)
	if err != nil {
		t.Fatalf("ExtractDecoy failed: %v", err)
	}
	if !bytes.HasPrefix(extractedDecoy, decoy) {
		t.Errorf("decoy mismatch")
	}

	extractedHidden, err := ExtractHidden(blob, offset)
	if err != nil {
		t.Fatalf("ExtractHidden failed: %v", err)
	}
	if !bytes.HasPrefix(extractedHidden, hidden) {
		t.Errorf("hidden mismatch")
	}
}

func TestDeniableFullFlow(t *testing.T) {
	keyDecoy, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	keyHidden, _ := crypto.GenerateRandomBytes(crypto.KeyLen)

	dbDecoy := NewMetadataDB()
	dbDecoy.Files["decoy"] = &types.FileRecord{ID: "decoy", Filename: "decoy.txt"}

	dbHidden := NewMetadataDB()
	dbHidden.Files["hidden"] = &types.FileRecord{ID: "hidden", Filename: "hidden.txt"}

	offset := 512 * 1024

	// Encrypt with padding
	encDecoy, err := EncryptMetadataDeniable(dbDecoy, keyDecoy, offset)
	if err != nil {
		t.Fatalf("EncryptMetadataDeniable (decoy) failed: %v", err)
	}

	encHidden, err := EncryptMetadataDeniable(dbHidden, keyHidden, MetadataBlobSize-offset)
	if err != nil {
		t.Fatalf("EncryptMetadataDeniable (hidden) failed: %v", err)
	}

	// Package
	blob, err := PackageDeniable(encDecoy, encHidden, offset)
	if err != nil {
		t.Fatalf("PackageDeniable failed: %v", err)
	}

	// Extract and Decrypt Decoy
	// Note: ExtractDecoy returns the whole 1MB, but our Decoy was padded to offset.
	// Since we know hiddenOffset, we use it.
	extDecoy := blob[:offset]
	decDecoy, err := DecryptMetadata(extDecoy, keyDecoy)
	if err != nil {
		t.Fatalf("DecryptMetadata (decoy) failed: %v", err)
	}
	if _, ok := decDecoy.Files["decoy"]; !ok {
		t.Errorf("decoy DB missing file")
	}

	// Extract and Decrypt Hidden
	extHidden, err := ExtractHidden(blob, offset)
	if err != nil {
		t.Fatalf("ExtractHidden failed: %v", err)
	}
	decHidden, err := DecryptMetadata(extHidden, keyHidden)
	if err != nil {
		t.Fatalf("DecryptMetadata (hidden) failed: %v", err)
	}
	if _, ok := decHidden.Files["hidden"]; !ok {
		t.Errorf("hidden DB missing file")
	}
}
