package cmd

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"google.golang.org/protobuf/proto"

	"github.com/vultisig/vultisig-cli/internal/storage"
	"github.com/vultisig/vultisig-cli/internal/vault"
)

// vaultCmd represents the vault command
var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage Vultisig vaults",
	Long:  `Create and manage Vultisig DKLS-based vaults`,
}

// createCmd represents the vault create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new vault",
	Long:  `Create a new DKLS-based vault by connecting to the Vultisig relay server`,
	RunE:  runCreate,
}

// listCmd represents the vault list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all vaults",
	Long:  `List all vaults stored in the local vault directory`,
	RunE:  runList,
}

// inspectCmd represents the vault inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect [vault-label-or-path]",
	Short: "Inspect a vault and display its details",
	Long: `Inspect a vault file and display all its details including public keys, keyshares, signers, and metadata.
You can provide either:
- A vault label/filename (e.g., "MyVault-abcd1234.vult") to inspect from the default vault directory
- An absolute path to a vault file anywhere on disk`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(createCmd)
	vaultCmd.AddCommand(listCmd)
	vaultCmd.AddCommand(inspectCmd)

	// Add flags for vault creation
	createCmd.Flags().StringP("name", "n", "", "Vault name (required)")
	createCmd.Flags().StringP("session", "s", uuid.New().String(), "Session ID (randomly generated if not provided)")
	createCmd.Flags().StringP("party", "p", "", "Local party ID (optional - hostname if not provided)")
	createCmd.Flags().StringP("relay", "r", "https://api.vultisig.com/router", "Relay server URL")
	createCmd.Flags().StringP("email", "m", "", "Email (required)")
	createCmd.Flags().StringP("password", "e", "", "Password for vault encryption on server (required)")

	createCmd.MarkFlagRequired("name")
	createCmd.MarkFlagRequired("email")
	createCmd.MarkFlagRequired("password")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	sessionID, _ := cmd.Flags().GetString("session")
	localPartyID, _ := cmd.Flags().GetString("party")
	relayServer, _ := cmd.Flags().GetString("relay")
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	// 32 random bytes
	hexChainCodeBytes := make([]byte, 32)
	if _, err := rand.Read(hexChainCodeBytes); err != nil {
		return fmt.Errorf("failed to generate chain code: %w", err)
	}
	hexChainCode := hex.EncodeToString(hexChainCodeBytes)

	// Generate encryption key if not provided
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}
	encryptionKey := hex.EncodeToString(keyBytes)
	fmt.Printf("Generated encryption key: %s\n", encryptionKey)

	var err error
	if localPartyID == "" {
		localPartyID, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}

		// normalize hostname to remove .local
		localPartyID = strings.TrimSuffix(localPartyID, ".local")
	}

	// Get vault directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	vaultDir := filepath.Join(homeDir, ".vultisig")

	// Initialize storage
	localStorage, err := storage.NewLocalVaultStorage(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize vault service
	vaultService := vault.NewService(relayServer, "cli-secret", localStorage)

	// Show connection info
	fmt.Printf("Creating vault '%s'...\n", name)
	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("Local Party ID: %s\n", localPartyID)
	fmt.Printf("Relay Server: %s\n", relayServer)
	fmt.Printf("Encryption Key: %s\n", encryptionKey)
	fmt.Printf("Email: %s\n", email)
	fmt.Println()

	// Confirm before proceeding
	if !askForConfirmation("Do you want to proceed with vault creation?") {
		fmt.Println("Vault creation cancelled.")
		return nil
	}

	// Create vault request
	req := vault.CreateVaultRequest{
		Name:               name,
		SessionID:          sessionID,
		LocalPartyId:       localPartyID,
		HexEncryptionKey:   encryptionKey,
		Email:              email,
		HexChainCode:       hexChainCode,
		EncryptionPassword: password,
	}

	fmt.Println("Starting vault creation...")
	fmt.Println("Waiting for other parties to join the session...")

	// Create the vault
	ecdsaKey, eddsaKey, err := vaultService.CreateVault(req)
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	fmt.Println("\n✅ Vault created successfully!")
	fmt.Printf("Vault Name: %s\n", name)
	fmt.Printf("ECDSA Public Key: %s\n", ecdsaKey)
	fmt.Printf("EdDSA Public Key: %s\n", eddsaKey)
	fmt.Printf("Vault saved to: %s\n", vaultDir)

	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	// Get vault directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	vaultDir := filepath.Join(homeDir, ".vultisig")

	// Initialize storage
	localStorage, err := storage.NewLocalVaultStorage(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// List vaults
	vaults, err := localStorage.ListVaults()
	if err != nil {
		return fmt.Errorf("failed to list vaults: %w", err)
	}

	if len(vaults) == 0 {
		fmt.Println("No vaults found in", vaultDir)
		return nil
	}

	fmt.Printf("Found %d vault(s) in %s:\n\n", len(vaults), vaultDir)
	for i, vault := range vaults {
		fmt.Printf("%d. %s\n", i+1, vault)
	}

	return nil
}

func runInspect(cmd *cobra.Command, args []string) error {
	vaultInput := args[0]
	
	// Determine if input is a path or a vault label
	var vaultData []byte
	var err error
	var vaultPath string
	
	if filepath.IsAbs(vaultInput) {
		// Absolute path provided - read directly
		vaultPath = vaultInput
		vaultData, err = os.ReadFile(vaultPath)
		if err != nil {
			return fmt.Errorf("failed to read vault file '%s': %w", vaultPath, err)
		}
	} else {
		// Vault label provided - look in default vault directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		vaultDir := filepath.Join(homeDir, ".vultisig")
		
		// Initialize storage
		localStorage, err := storage.NewLocalVaultStorage(vaultDir)
		if err != nil {
			return fmt.Errorf("failed to initialize storage: %w", err)
		}
		
		// Try to read the vault by label
		vaultData, err = localStorage.GetVault(vaultInput)
		if err != nil {
			return fmt.Errorf("failed to read vault '%s': %w", vaultInput, err)
		}
		vaultPath = filepath.Join(vaultDir, vaultInput)
	}
	
	// Parse the vault container - handle both base64 and raw protobuf formats
	var vaultContainer vaultType.VaultContainer
	
	// First try to parse as base64-encoded protobuf (vultisig-windows format)
	if base64Data, err := base64.StdEncoding.DecodeString(string(vaultData)); err == nil {
		if err := proto.Unmarshal(base64Data, &vaultContainer); err == nil {
			// Successfully parsed as base64 format
		} else {
			// Try parsing the original data as raw protobuf (old CLI format)
			if err := proto.Unmarshal(vaultData, &vaultContainer); err != nil {
				return fmt.Errorf("failed to unmarshal vault container (tried both base64 and raw formats): %w", err)
			}
		}
	} else {
		// Not valid base64, try as raw protobuf
		if err := proto.Unmarshal(vaultData, &vaultContainer); err != nil {
			return fmt.Errorf("failed to unmarshal vault container: %w", err)
		}
	}
	
	// Decode the vault data
	vaultBytes, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return fmt.Errorf("failed to decode vault data: %w", err)
	}
	
	// If encrypted, we would need to decrypt here
	if vaultContainer.IsEncrypted {
		return fmt.Errorf("encrypted vaults are not supported yet - vault decryption requires password")
	}
	
	// Parse the vault
	var vault vaultType.Vault
	if err := proto.Unmarshal(vaultBytes, &vault); err != nil {
		return fmt.Errorf("failed to unmarshal vault: %w", err)
	}
	
	// Display vault information
	fmt.Printf("🔍 Vault Inspection Report\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")
	
	// Basic Information
	fmt.Printf("📁 Basic Information:\n")
	fmt.Printf("   Name: %s\n", vault.Name)
	fmt.Printf("   File Path: %s\n", vaultPath)
	fmt.Printf("   Local Party ID: %s\n", vault.LocalPartyId)
	fmt.Printf("   Reshare Prefix: %s\n", vault.ResharePrefix)
	if vault.CreatedAt != nil {
		fmt.Printf("   Created At: %s\n", vault.CreatedAt.AsTime().Format(time.RFC3339))
	}
	fmt.Printf("\n")
	
	// Library Type
	fmt.Printf("🔧 Library Type:\n")
	libTypeStr := "Unknown"
	switch vault.LibType {
	case keygen.LibType_LIB_TYPE_GG20:
		libTypeStr = "GG20 (ECDSA TSS)"
	case keygen.LibType_LIB_TYPE_DKLS:
		libTypeStr = "DKLS (Distributed Key Generation and Signing)"
	}
	fmt.Printf("   %s (%d)\n", libTypeStr, int32(vault.LibType))
	fmt.Printf("\n")
	
	// Container Information
	fmt.Printf("📦 Container Information:\n")
	fmt.Printf("   Version: %d\n", vaultContainer.Version)
	fmt.Printf("   Is Encrypted: %v\n", vaultContainer.IsEncrypted)
	fmt.Printf("   Container Size: %d bytes\n", len(vaultData))
	fmt.Printf("   Vault Data Size: %d bytes\n", len(vaultBytes))
	fmt.Printf("\n")
	
	// Public Keys
	fmt.Printf("🔑 Public Keys:\n")
	fmt.Printf("   ECDSA: %s\n", vault.PublicKeyEcdsa)
	fmt.Printf("   EdDSA: %s\n", vault.PublicKeyEddsa)
	if vault.HexChainCode != "" {
		fmt.Printf("   Chain Code: %s\n", vault.HexChainCode)
	}
	fmt.Printf("\n")
	
	// Signers
	fmt.Printf("👥 Signers (%d total):\n", len(vault.Signers))
	for i, signer := range vault.Signers {
		marker := "   "
		if signer == vault.LocalPartyId {
			marker = " ➤ "
		}
		fmt.Printf("%s[%d] %s\n", marker, i+1, signer)
	}
	fmt.Printf("\n")
	
	// Key Shares
	fmt.Printf("🔐 Key Shares (%d total):\n", len(vault.KeyShares))
	for i, keyShare := range vault.KeyShares {
		fmt.Printf("   [%d] Public Key: %s\n", i+1, keyShare.PublicKey)
		
		// Determine key type
		keyType := "Unknown"
		if keyShare.PublicKey == vault.PublicKeyEcdsa {
			keyType = "ECDSA"
		} else if keyShare.PublicKey == vault.PublicKeyEddsa {
			keyType = "EdDSA"
		}
		fmt.Printf("       Type: %s\n", keyType)
		
		// Show keyshare info (truncated for security)
		if len(keyShare.Keyshare) > 0 {
			keyshareBytes, err := base64.StdEncoding.DecodeString(keyShare.Keyshare)
			var keyshareInfo string
			if err != nil {
				keyshareInfo = "Invalid base64"
			} else {
				keyshareInfo = fmt.Sprintf("%d bytes", len(keyshareBytes))
				if len(keyShare.Keyshare) > 16 {
					keyshareInfo += fmt.Sprintf(" (%s...)", keyShare.Keyshare[:16])
				}
			}
			fmt.Printf("       Keyshare: %s\n", keyshareInfo)
		}
		
		if i < len(vault.KeyShares)-1 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")
	
	// Security Notice
	fmt.Printf("⚠️  Security Notice:\n")
	fmt.Printf("   This vault contains sensitive cryptographic material.\n")
	fmt.Printf("   Keep the vault file secure and never share keyshares.\n")
	fmt.Printf("   The displayed keyshare data is truncated for security.\n")
	
	return nil
}

func askForConfirmation(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", question)

	response, err := reader.ReadString('\n')
	if err != nil {
		logrus.WithError(err).Error("Failed to read user input")
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
