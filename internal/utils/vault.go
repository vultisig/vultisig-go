package utils

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"google.golang.org/protobuf/proto"

	"github.com/vultisig/vultisig-go/common"
	"github.com/vultisig/vultisig-go/internal/storage"
)

// VaultLoader handles loading and parsing vault files from various sources
type VaultLoader struct {
	storage *storage.LocalVaultStorage
}

// NewVaultLoader creates a new vault loader with storage
func NewVaultLoader(storage *storage.LocalVaultStorage) *VaultLoader {
	return &VaultLoader{storage: storage}
}

// LoadVaultData loads vault data from either an absolute path or vault label
func (vl *VaultLoader) LoadVaultData(vaultInput string) ([]byte, string, error) {
	var vaultData []byte
	var err error
	var vaultPath string

	if filepath.IsAbs(vaultInput) {
		// Absolute path provided - read directly
		vaultPath = vaultInput
		vaultData, err = os.ReadFile(vaultPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read vault file '%s': %w", vaultPath, err)
		}
	} else {
		// Vault label provided - look in default vault directory
		if vl.storage == nil {
			return nil, "", fmt.Errorf("storage not initialized for vault label lookup")
		}

		// Try to read the vault by label
		vaultData, err = vl.storage.GetVault(vaultInput)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read vault '%s': %w", vaultInput, err)
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get home directory: %w", err)
		}
		vaultPath = filepath.Join(homeDir, ".vultisig", vaultInput)
	}

	return vaultData, vaultPath, nil
}

// ParseVaultContainer parses vault data into a VaultContainer, handling both formats
func ParseVaultContainer(vaultData []byte) (*vaultType.VaultContainer, error) {
	var vaultContainer vaultType.VaultContainer

	// First try to parse as base64-encoded protobuf (vultisig-windows format)
	if base64Data, err := base64.StdEncoding.DecodeString(string(vaultData)); err == nil {
		if err := proto.Unmarshal(base64Data, &vaultContainer); err == nil {
			// Successfully parsed as base64 format
			return &vaultContainer, nil
		} else {
			// Try parsing the original data as raw protobuf (old CLI format)
			if err := proto.Unmarshal(vaultData, &vaultContainer); err != nil {
				return nil, fmt.Errorf("failed to unmarshal vault container (tried both base64 and raw formats): %w", err)
			}
		}
	} else {
		// Not valid base64, try as raw protobuf
		if err := proto.Unmarshal(vaultData, &vaultContainer); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vault container: %w", err)
		}
	}

	return &vaultContainer, nil
}

// ParseVault extracts and parses the vault from a container
func ParseVault(vaultContainer *vaultType.VaultContainer) (*vaultType.Vault, error) {
	// Decode the vault data
	vaultBytes, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault data: %w", err)
	}

	// Parse the vault
	var vault vaultType.Vault
	if err := proto.Unmarshal(vaultBytes, &vault); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	return &vault, nil
}

// LoadAndParseVault is a convenience function that loads and parses a vault in one step
func (vl *VaultLoader) LoadAndParseVault(vaultInput string, localPassword string) (*vaultType.Vault, *vaultType.VaultContainer, string, error) {
	vaultData, vaultPath, err := vl.LoadVaultData(vaultInput)
	if err != nil {
		return nil, nil, "", err
	}

	vaultContainer, err := ParseVaultContainer(vaultData)
	if err != nil {
		return nil, nil, "", err
	}

	if localPassword != "" && vaultContainer.IsEncrypted {
		vaultBytes, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			return nil, nil, "", err
		}
		vaultBytes, err = common.DecryptVault(localPassword, vaultBytes)
		if err != nil {
			return nil, nil, "", err
		}
		vaultContainer.Vault = base64.StdEncoding.EncodeToString(vaultBytes)
	} else if localPassword == "" && vaultContainer.IsEncrypted {
		return nil, nil, "", fmt.Errorf("local password is required to decrypt vault")
	}

	vault, err := ParseVault(vaultContainer)
	if err != nil {
		return nil, nil, "", err
	}

	return vault, vaultContainer, vaultPath, nil
}
