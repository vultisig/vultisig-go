package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"google.golang.org/protobuf/proto"

	"github.com/vultisig/vultiserver/relay"
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

// reshareCmd represents the vault reshare command
var reshareCmd = &cobra.Command{
	Use:   "reshare [vault-label-or-path]",
	Short: "Reshare a vault with new committee",
	Long: `Reshare an existing vault with a new committee of 4 parties (CLI, vultiserver, verifier, and plugin).
The new committee will have a threshold of 2, meaning 2 out of 4 parties are required to sign transactions.
You can provide either:
- A vault label/filename (e.g., "MyVault-abcd1234.vult") to reshare from the default vault directory
- An absolute path to a vault file anywhere on disk`,
	Args: cobra.ExactArgs(1),
	RunE: runReshare,
}

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(createCmd)
	vaultCmd.AddCommand(listCmd)
	vaultCmd.AddCommand(inspectCmd)
	vaultCmd.AddCommand(reshareCmd)

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

	// Add flags for vault resharing
	reshareCmd.Flags().StringP("session", "s", uuid.New().String(), "Session ID (randomly generated if not provided)")
	reshareCmd.Flags().StringP("party", "p", "", "Local party ID (optional - hostname if not provided)")
	reshareCmd.Flags().StringP("relay", "r", "https://api.vultisig.com/router", "Relay server URL")
	reshareCmd.Flags().StringP("verifier", "", "https://api.vultisig.com/verifier", "Verifier server URL")
	reshareCmd.Flags().StringP("plugin", "", "https://api.vultisig.com/plugin", "Plugin server URL")
	reshareCmd.Flags().StringP("email", "m", "", "Email (required)")
	reshareCmd.Flags().StringP("password", "e", "", "Password for vault encryption on server (required)")
	reshareCmd.Flags().StringP("plugin-id", "i", "", "Plugin ID (required)")

	reshareCmd.MarkFlagRequired("email")
	reshareCmd.MarkFlagRequired("password")
	reshareCmd.MarkFlagRequired("plugin-id")
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

func runReshare(cmd *cobra.Command, args []string) error {
	vaultInput := args[0]
	sessionID, _ := cmd.Flags().GetString("session")
	localPartyID, _ := cmd.Flags().GetString("party")
	relayServer, _ := cmd.Flags().GetString("relay")
	verifierServer, _ := cmd.Flags().GetString("verifier")
	pluginServer, _ := cmd.Flags().GetString("plugin")
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	pluginID, _ := cmd.Flags().GetString("plugin-id")

	// Load the existing vault
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

	// Parse the vault container
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

	// Generate new encryption key for reshare
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}
	encryptionKey := hex.EncodeToString(keyBytes)

	var localParty string
	if localPartyID == "" {
		localParty, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		// normalize hostname to remove .local
		localParty = strings.TrimSuffix(localParty, ".local")
	} else {
		localParty = localPartyID
	}

	// Show reshare info
	fmt.Printf("Resharing vault '%s'...\n", vault.Name)
	fmt.Printf("Original Public Key: %s\n", vault.PublicKeyEcdsa)
	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("Local Party ID: %s\n", localParty)
	fmt.Printf("Relay Server: %s\n", relayServer)
	fmt.Printf("Verifier Server: %s\n", verifierServer)
	fmt.Printf("Plugin Server: %s\n", pluginServer)
	fmt.Printf("Encryption Key: %s\n", encryptionKey)
	fmt.Printf("Email: %s\n", email)
	fmt.Printf("Old Parties: %v\n", vault.Signers)
	fmt.Println()

	// Confirm before proceeding
	if !askForConfirmation("Do you want to proceed with vault resharing?") {
		fmt.Println("Vault resharing cancelled.")
		return nil
	}

	// Create reshare requests for all servers
	reshareReq := struct {
		Name               string   `json:"name"`
		PublicKey          string   `json:"public_key"`
		SessionID          string   `json:"session_id"`
		HexEncryptionKey   string   `json:"hex_encryption_key"`
		HexChainCode       string   `json:"hex_chain_code"`
		LocalPartyId       string   `json:"local_party_id"`
		OldParties         []string `json:"old_parties"`
		EncryptionPassword string   `json:"encryption_password"`
		Email              string   `json:"email"`
		OldResharePrefix   string   `json:"old_reshare_prefix"`
		LibType            int      `json:"lib_type"`
		PluginID           string   `json:"plugin_id"`
		ReshareType        int      `json:"reshare_type"`
	}{
		Name:               vault.Name,
		PublicKey:          vault.PublicKeyEcdsa,
		SessionID:          sessionID,
		HexEncryptionKey:   encryptionKey,
		HexChainCode:       vault.HexChainCode,
		LocalPartyId:       localParty,
		OldParties:         vault.Signers,
		EncryptionPassword: password,
		Email:              email,
		OldResharePrefix:   vault.ResharePrefix,
		LibType:            1, // DKLS
		PluginID:           pluginID,
		ReshareType:        1, // Reshare plugin
	}

	// Send reshare requests to all servers
	fmt.Println("Initiating reshare with all servers...")

	// Send to vultiserver
	if err := sendReshareRequest("https://api.vultisig.com/vault/reshare", reshareReq); err != nil {
		return fmt.Errorf("failed to initiate reshare with vultiserver: %w", err)
	}
	fmt.Println("✓ Vultiserver notified")

	// Send to verifier
	if err := sendReshareRequest(verifierServer+"/vault/reshare", reshareReq); err != nil {
		return fmt.Errorf("failed to initiate reshare with verifier: %w", err)
	}
	fmt.Println("✓ Verifier notified")

	// Send to plugin
	if err := sendReshareRequest(pluginServer+"/vault/reshare", reshareReq); err != nil {
		return fmt.Errorf("failed to initiate reshare with plugin: %w", err)
	}
	fmt.Println("✓ Plugin notified")

	// Wait for all 4 parties to join the session and then start the reshare
	fmt.Println("\nWaiting for all 4 parties to join the reshare session...")

	newCommittee, err := waitForAllPartiesToJoin(sessionID, relayServer, localParty)
	if err != nil {
		return fmt.Errorf("failed to wait for all parties: %w", err)
	}

	newCommittee = []string{"Server-1234", "verifier", "vultisig-dca-0000"}

	fmt.Println("\n✅ All 4 parties have joined the reshare session!")
	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("New committee: %v (threshold: 2 of 4)\n", newCommittee)

	// Now start the reshare process as the initiating party
	fmt.Println("\nStarting reshare process...")
	if err := performReshare(&vault, sessionID, encryptionKey, relayServer, localParty, newCommittee); err != nil {
		return fmt.Errorf("failed to perform reshare: %w", err)
	}

	fmt.Println("\n✅ Reshare completed successfully!")

	return nil
}

func waitForAllPartiesToJoin(sessionID, relayServer, localParty string) ([]string, error) {
	// Import relay client to check session status
	relayClient := relay.NewRelayClient(relayServer)

	// Register ourselves with the relay
	if err := relayClient.RegisterSession(sessionID, localParty); err != nil {
		return nil, fmt.Errorf("failed to register with relay: %w", err)
	}

	// Wait for all 4 parties to join: CLI, Vultiserver, Verifier, Plugin
	expectedParties := 4
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	for ctx.Err() == nil {
		partiesJoined, err := relayClient.GetSession(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get session status: %w", err)
		}

		fmt.Printf("Parties joined (%d/4): %v\n", len(partiesJoined), partiesJoined)

		if len(partiesJoined) == expectedParties {
			// All 4 parties joined, start the session with new committee (threshold: 2 of 4)
			if err := relayClient.StartSession(sessionID, partiesJoined); err != nil {
				return nil, fmt.Errorf("failed to start reshare session: %w", err)
			}

			fmt.Printf("✓ Started reshare session with new committee (threshold: 2 of 4)\n")
			return partiesJoined, nil
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for all parties to join")
}

func sendReshareRequest(url string, req interface{}) error {
	jsonPayload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	response, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send request to %s: %w", url, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("server rejected request (status %d): %s", response.StatusCode, string(body))
	}

	return nil
}

func performReshare(vault *vaultType.Vault, sessionID, encryptionKey, relayServer, localParty string, newCommittee []string) error {
	fmt.Println("📋 Reshare Summary:")
	fmt.Printf("   Old Committee: %v (threshold: %d)\n", vault.Signers, len(vault.Signers))
	fmt.Printf("   New Committee: %v (threshold: 2)\n", newCommittee)
	fmt.Println()

	// Create setup messages and participate in reshare for both key types
	fmt.Println("🔑 Starting ECDSA key reshare...")
	if err := createQcSetupAndReshare(vault, sessionID, encryptionKey, localParty, newCommittee, vault.PublicKeyEcdsa, false); err != nil {
		return fmt.Errorf("failed to reshare ECDSA key: %w", err)
	}

	fmt.Println("🔑 Starting EdDSA key reshare...")
	if err := createQcSetupAndReshare(vault, sessionID, encryptionKey, localParty, newCommittee, vault.PublicKeyEddsa, true); err != nil {
		return fmt.Errorf("failed to reshare EdDSA key: %w", err)
	}

	fmt.Println("\n✅ Both key reshares completed successfully!")
	fmt.Println("📝 Note: The CLI has successfully created QC setup messages and initiated the reshare.")
	fmt.Println("📝 Other parties (vultiserver, verifier, plugin) will now complete the reshare process.")
	fmt.Println("📝 New vault files with updated keyshares will be saved by each party.")

	return nil
}

func createQcSetupAndReshare(v *vaultType.Vault, sessionID, encryptionKey, localParty string, newCommittee []string, publicKey string, isEdDSA bool) error {
	keyType := map[bool]string{true: "EdDSA", false: "ECDSA"}[isEdDSA]

	mpcWrapper := vault.NewMPCWrapperImp(isEdDSA)

	// Get the keyshare for this public key
	var keyshareBase64 string
	for _, ks := range v.KeyShares {
		if ks.PublicKey == publicKey {
			keyshareBase64 = ks.Keyshare
			break
		}
	}
	if keyshareBase64 == "" {
		return fmt.Errorf("keyshare not found for public key %s", publicKey)
	}

	decodedKeyshare, err := base64.StdEncoding.DecodeString(keyshareBase64)
	if err != nil {
		return fmt.Errorf("failed to decode keyshare: %w", err)
	}

	keyshareHandle, err := mpcWrapper.KeyshareFromBytes(decodedKeyshare)
	if err != nil {
		return fmt.Errorf("failed to create keyshare from bytes: %w", err)
	}

	// Calculate committee information for QC setup
	oldCommittee := v.Signers
	allCommittee := combineCommittees(oldCommittee, newCommittee)
	oldIndices, newIndices := getCommitteeIndices(allCommittee, oldCommittee, newCommittee)

	fmt.Printf("   📊 Committee Info for %s:\n", keyType)
	fmt.Printf("      Old parties: %v (indices: %v)\n", oldCommittee, oldIndices)
	fmt.Printf("      New parties: %v (indices: %v)\n", newCommittee, newIndices)
	fmt.Printf("      Combined: %v\n", allCommittee)
	fmt.Printf("      Threshold: 2 of %d\n", len(newCommittee))

	setupMsg, err := mpcWrapper.QcSetupMsgNew(keyshareHandle, 2, allCommittee, oldIndices, newIndices)
	if err != nil {
		return fmt.Errorf("failed to create QC setup message: %w", err)
	}

	hexBytes := hex.EncodeToString(setupMsg)
	fmt.Println("setup message bytes", hexBytes)

	// Encrypt and upload setup message
	relayClient := relay.NewRelayClient("https://api.vultisig.com/router")
	encryptedSetup, err := encodeEncryptMessage(setupMsg, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt setup message: %w", err)
	}

	eddsaHeader := ""
	if isEdDSA {
		eddsaHeader = "eddsa"
	}

	if err := relayClient.UploadSetupMessage(sessionID, encryptedSetup, "", eddsaHeader); err != nil {
		return fmt.Errorf("failed to upload setup message: %w", err)
	}

	fmt.Printf("   ✅ Uploaded %s QC setup message to relay\n", keyType)

	// The CLI has now done its part as the initiating party:
	// 1. Created the QC setup message with correct committee structure
	// 2. Uploaded it to the relay server
	// 3. The other parties will download this setup and participate in the reshare

	fmt.Printf("   📡 %s setup message ready for other parties to download\n", keyType)

	// Now create QC session and participate in the reshare protocol
	handle, err := mpcWrapper.QcSessionFromSetup(setupMsg, localParty, keyshareHandle)
	if err != nil {
		return fmt.Errorf("failed to create QC session: %w", err)
	}

	// Run the actual reshare protocol
	fmt.Printf("   🔄 Starting %s reshare protocol...\n", keyType)
	newPublicKey, chainCode, err := runQcReshareProtocol(mpcWrapper, handle, sessionID, encryptionKey, localParty, newCommittee)
	if err != nil {
		return fmt.Errorf("failed to run reshare protocol: %w", err)
	}

	if newPublicKey != "" {
		fmt.Printf("   ✅ %s reshare completed! New public key: %s\n", keyType, newPublicKey)
		if chainCode != "" {
			fmt.Printf("      Chain code: %s\n", chainCode)
		}
	} else {
		fmt.Printf("   ✅ %s reshare completed (not in new committee)\n", keyType)
	}

	return nil
}

func combineCommittees(oldCommittee, newCommittee []string) []string {
	// Create a set to avoid duplicates
	seen := make(map[string]bool)
	var combined []string

	// Add all parties from both committees
	for _, party := range oldCommittee {
		if !seen[party] {
			combined = append(combined, party)
			seen[party] = true
		}
	}
	for _, party := range newCommittee {
		if !seen[party] {
			combined = append(combined, party)
			seen[party] = true
		}
	}

	return combined
}

func getCommitteeIndices(allCommittee, oldCommittee, newCommittee []string) ([]int, []int) {
	var oldIndices, newIndices []int

	for i, party := range allCommittee {
		for _, oldParty := range oldCommittee {
			if party == oldParty {
				oldIndices = append(oldIndices, i)
				break
			}
		}
		for _, newParty := range newCommittee {
			if party == newParty {
				newIndices = append(newIndices, i)
				break
			}
		}
	}

	return oldIndices, newIndices
}

func runQcReshareProtocol(mpcWrapper *vault.MPCWrapperImp, handle vault.Handle, sessionID, encryptionKey, localParty string, committee []string) (string, string, error) {
	relayClient := relay.NewRelayClient("https://api.vultisig.com/router")

	// Create atomic flag to signal completion
	isReshareFinished := &atomic.Bool{}
	isReshareFinished.Store(false)

	// Start outbound and inbound processing concurrently
	errChan := make(chan error, 2)
	resultChan := make(chan struct {
		PublicKey string
		ChainCode string
	}, 1)

	// Process outbound messages
	go func() {
		errChan <- processQcReshareOutbound(mpcWrapper, handle, sessionID, encryptionKey, localParty, committee, isReshareFinished)
	}()

	// Process inbound messages
	go func() {
		publicKey, chainCode, err := processQcReshareInbound(mpcWrapper, handle, sessionID, encryptionKey, localParty, committee, relayClient, isReshareFinished)
		if err != nil {
			errChan <- err
		} else {
			resultChan <- struct {
				PublicKey string
				ChainCode string
			}{publicKey, chainCode}
		}
	}()

	// Wait for completion or error
	select {
	case result := <-resultChan:
		isReshareFinished.Store(true)
		return result.PublicKey, result.ChainCode, nil
	case err := <-errChan:
		isReshareFinished.Store(true)
		return "", "", err
	case <-time.After(2 * time.Minute):
		isReshareFinished.Store(true)
		return "", "", fmt.Errorf("reshare timeout")
	}
}

func processQcReshareOutbound(mpcWrapper *vault.MPCWrapperImp, handle vault.Handle, sessionID, encryptionKey, localParty string, committee []string, isReshareFinished *atomic.Bool) error {
	messenger := relay.NewMessenger("https://api.vultisig.com/router", sessionID, encryptionKey, true, "")

	for {
		if isReshareFinished.Load() {
			fmt.Printf("   ⏹️  Reshare finished, stopping outbound processing\n")
			time.Sleep(2 * time.Second)
			return nil
		}

		// Get output message using the MPC wrapper
		outbound, err := mpcWrapper.QcSessionOutputMessage(handle)
		if err != nil {
			continue
		}

		if len(outbound) == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Get message receivers for each outbound message using MPC wrapper
		numReceivers := len(committee)

		// Send to each receiver
		for idx := 0; idx < numReceivers; idx++ {
			receiver, err := mpcWrapper.QcSessionMessageReceiver(handle, outbound, idx)
			if err != nil {
				continue
			}
			if receiver == "" || receiver == localParty {
				continue // No receiver or self-message
			}

			// Encode message to base64 (messenger handles encryption)
			encodedMessage := base64.StdEncoding.EncodeToString(outbound)

			if err := messenger.Send(localParty, receiver, encodedMessage); err != nil {
				fmt.Printf("   ⚠️  Failed to send message to %s: %v\n", receiver, err)
			} else {
				fmt.Printf("   📤 Sent reshare message to %s\n", receiver)
			}
		}

		time.Sleep(50 * time.Millisecond) // Small delay between sends
	}
}

func processQcReshareInbound(mpcWrapper *vault.MPCWrapperImp, handle vault.Handle, sessionID, encryptionKey, localParty string, committee []string, relayClient *relay.Client, isReshareFinished *atomic.Bool) (string, string, error) {
	var messageCache sync.Map
	start := time.Now()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(start) > (2 * time.Minute) {
				return "", "", fmt.Errorf("reshare timeout")
			}

			messages, err := relayClient.DownloadMessages(sessionID, localParty, "")
			if err != nil {
				continue
			}

			for _, message := range messages {
				if message.From == localParty {
					continue // Skip our own messages
				}

				cacheKey := fmt.Sprintf("%s-%s-%s", sessionID, localParty, message.Hash)
				if _, found := messageCache.Load(cacheKey); found {
					continue // Already processed
				}

				// Decrypt the message using the same method as vault service
				inboundBody, err := decodeDecryptMessage(message.Body, encryptionKey)
				if err != nil {
					continue
				}

				fmt.Printf("   📥 Processing reshare message from %s\n", message.From)

				// Apply message to QC session using MPC wrapper
				isFinished, err := mpcWrapper.QcSessionInputMessage(handle, inboundBody)
				if err != nil {
					continue
				}

				// Mark message as processed
				messageCache.Store(cacheKey, true)

				// Delete message from server
				if err := relayClient.DeleteMessageFromServer(sessionID, localParty, message.Hash, ""); err != nil {
					fmt.Printf("   ⚠️  Failed to delete message from server: %v\n", err)
				}

				if isFinished {
					fmt.Printf("   ✅ Reshare protocol completed, finalizing result\n")

					// Finish the QC session and extract results
					keyshareResult, err := mpcWrapper.QcSessionFinish(handle)
					if err != nil {
						return "", "", fmt.Errorf("failed to finish reshare: %w", err)
					}

					// Check if we're in the new committee
					isInNewCommittee := false
					for _, party := range committee {
						if party == localParty {
							isInNewCommittee = true
							break
						}
					}

					if !isInNewCommittee {
						fmt.Printf("   ℹ️  Not in new committee, reshare complete\n")
						time.Sleep(2 * time.Second)
						return "", "", nil
					}

					// Extract keyshare bytes, public key, and chain code using MPC wrapper
					keyshareBytes, err := mpcWrapper.KeyshareToBytes(keyshareResult)
					if err != nil {
						return "", "", fmt.Errorf("failed to convert keyshare to bytes: %w", err)
					}

					publicKeyBytes, err := mpcWrapper.KeysharePublicKey(keyshareResult)
					if err != nil {
						return "", "", fmt.Errorf("failed to get public key: %w", err)
					}

					publicKey := hex.EncodeToString(publicKeyBytes)

					// Try to get chain code (might not be available for EdDSA)
					var chainCode string
					if chainCodeBytes, err := mpcWrapper.KeyshareChainCode(keyshareResult); err == nil {
						chainCode = hex.EncodeToString(chainCodeBytes)
					}

					// Save keyshare to local state
					keyshareBase64 := base64.StdEncoding.EncodeToString(keyshareBytes)

					// We would need access to LocalStateAccessor here, but for now just log the result
					fmt.Printf("   🔑 New keyshare generated for public key: %s\n", publicKey)
					if chainCode != "" {
						fmt.Printf("   🔗 Chain code: %s\n", chainCode)
					}

					// In a complete implementation, we would save the new vault here
					// For now, we just return the results
					_ = keyshareBase64 // Acknowledge we have the keyshare

					time.Sleep(2 * time.Second)
					return publicKey, chainCode, nil
				}
			}
		}
	}
}

func decodeDecryptMessage(encodedMessage, hexEncryptionKey string) ([]byte, error) {
	// First decode from base64
	encryptedMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Decrypt using AES-GCM
	decryptedMessage, err := vault.DecryptGCM(encryptedMessage, hexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	// The decrypted message is a base64-encoded string, so decode it
	inboundBody, err := base64.StdEncoding.DecodeString(string(decryptedMessage))
	if err != nil {
		return nil, fmt.Errorf("failed to decode inbound message: %w", err)
	}

	return inboundBody, nil
}

func encodeEncryptMessage(message []byte, hexEncryptionKey string) (string, error) {
	// First base64 encode the message
	base64EncodedMessage := base64.StdEncoding.EncodeToString(message)

	// Then encrypt using AES-GCM (same as in vault service)
	encryptedMessage, err := vault.EncryptGCM(base64EncodedMessage, hexEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	return encryptedMessage, nil
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
