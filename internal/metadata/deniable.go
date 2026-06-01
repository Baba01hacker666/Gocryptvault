package metadata

import (
	"crypto/rand"
	"fmt"
)

// MetadataBlobSize is the fixed size for the deniable metadata blob (1MB).
const MetadataBlobSize = 1024 * 1024
const DecoyBlobSize = 512 * 1024
const HiddenBlobSize = 256 * 1024

// PackageDeniable packages two separate encrypted metadata databases into a single 1MB blob.
// It fills the 1MB buffer with random data, then copies decoyBlob at the start and hiddenBlob at hiddenOffset.
func PackageDeniable(decoyBlob, hiddenBlob []byte, hiddenOffset int) ([]byte, error) {
	if len(decoyBlob) > hiddenOffset {
		return nil, fmt.Errorf("decoy blob too large for hidden offset %d", hiddenOffset)
	}
	if hiddenOffset+len(hiddenBlob) > MetadataBlobSize {
		return nil, fmt.Errorf("hidden blob exceeds metadata blob size at offset %d", hiddenOffset)
	}

	blob := make([]byte, MetadataBlobSize)
	if _, err := rand.Read(blob); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}

	copy(blob[0:], decoyBlob)
	copy(blob[hiddenOffset:], hiddenBlob)

	return blob, nil
}

// ExtractDecoy extracts the decoy metadata from the blob.
func ExtractDecoy(blob []byte) ([]byte, error) {
	if len(blob) != MetadataBlobSize {
		return nil, fmt.Errorf("invalid metadata blob size: expected %d, got %d", MetadataBlobSize, len(blob))
	}
	return blob[:DecoyBlobSize], nil
}

// ExtractHidden extracts the hidden metadata from the blob at the specified offset.
func ExtractHidden(blob []byte, hiddenOffset int) ([]byte, error) {
	if len(blob) != MetadataBlobSize {
		return nil, fmt.Errorf("invalid metadata blob size: expected %d, got %d", MetadataBlobSize, len(blob))
	}
	if hiddenOffset < 0 || hiddenOffset+HiddenBlobSize > MetadataBlobSize {
		return nil, fmt.Errorf("invalid hidden offset: %d", hiddenOffset)
	}
	return blob[hiddenOffset : hiddenOffset+HiddenBlobSize], nil
}
