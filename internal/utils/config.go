package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vultisig/vultisig-go/internal/storage"
)

// GetVaultDirectory returns the standard vault directory path
func GetVaultDirectory() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".vultisig"), nil
}

// InitializeStorage creates a new local vault storage instance
func InitializeStorage() (*storage.LocalVaultStorage, error) {
	vaultDir, err := GetVaultDirectory()
	if err != nil {
		return nil, err
	}

	localStorage, err := storage.NewLocalVaultStorage(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	return localStorage, nil
}

// GenerateEncryptionKey generates a new 32-byte encryption key
func GenerateEncryptionKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return hex.EncodeToString(keyBytes), nil
}

// GenerateChainCode generates a new 32-byte chain code
func GenerateChainCode() (string, error) {
	chainCodeBytes := make([]byte, 32)
	if _, err := rand.Read(chainCodeBytes); err != nil {
		return "", fmt.Errorf("failed to generate chain code: %w", err)
	}
	return hex.EncodeToString(chainCodeBytes), nil
}

// GetLocalPartyID returns the local party ID, using hostname if not provided
func GetLocalPartyID(providedID string) (string, error) {
	if providedID != "" {
		return providedID, nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}

	// Normalize hostname to remove .local
	return strings.TrimSuffix(hostname, ".local"), nil
}
