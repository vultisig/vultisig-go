package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// LocalVaultStorage manages vault storage in the local filesystem
type LocalVaultStorage struct {
	baseDir string
}

// NewLocalVaultStorage creates a new instance of LocalVaultStorage
func NewLocalVaultStorage(baseDir string) (*LocalVaultStorage, error) {
	// Create the base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	return &LocalVaultStorage{
		baseDir: baseDir,
	}, nil
}

// SaveVault saves vault data to a file
func (lvs *LocalVaultStorage) SaveVault(fileName string, content []byte) error {
	filePath := filepath.Join(lvs.baseDir, fileName)
	
	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Write the vault file
	if err := os.WriteFile(filePath, content, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	return nil
}

// GetVault retrieves vault data from a file
func (lvs *LocalVaultStorage) GetVault(fileName string) ([]byte, error) {
	filePath := filepath.Join(lvs.baseDir, fileName)
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("vault file not found: %s", fileName)
		}
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	return content, nil
}

// Exists checks if a vault file exists
func (lvs *LocalVaultStorage) Exists(fileName string) (bool, error) {
	filePath := filepath.Join(lvs.baseDir, fileName)
	
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check vault file: %w", err)
	}

	return true, nil
}

// ListVaults returns a list of all vault files
func (lvs *LocalVaultStorage) ListVaults() ([]string, error) {
	var vaults []string
	
	err := filepath.Walk(lvs.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && (filepath.Ext(path) == ".vult" || filepath.Ext(path) == ".bak") {
			relPath, err := filepath.Rel(lvs.baseDir, path)
			if err != nil {
				return err
			}
			vaults = append(vaults, relPath)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}
	
	return vaults, nil
}