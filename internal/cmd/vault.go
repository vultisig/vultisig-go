package cmd

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultisig-go/internal/utils"
	"github.com/vultisig/vultisig-go/internal/vault"
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
	createCmd.Flags().StringP("local-password", "l", "", "Local password for vault encryption")

	createCmd.MarkFlagRequired("name")
	createCmd.MarkFlagRequired("email")
	createCmd.MarkFlagRequired("password")

	// Add flags for vault resharing
	reshareCmd.Flags().StringP("session", "s", uuid.New().String(), "Session ID (randomly generated if not provided)")
	reshareCmd.Flags().StringP("party", "p", "", "Local party ID (optional - hostname if not provided)")
	reshareCmd.Flags().StringP("relay", "r", "https://api.vultisig.com/router", "Relay server URL")
	reshareCmd.Flags().StringP("verifier", "", "https://api.vultisig.com/verifier", "Verifier server URL")
	reshareCmd.Flags().StringP("email", "m", "", "Email (required)")
	reshareCmd.Flags().StringP("password", "e", "", "Password for vault encryption on server (required)")
	reshareCmd.Flags().StringP("plugin-id", "i", "", "Plugin ID (required)")
	reshareCmd.Flags().StringP("local-password", "l", "", "Local password for vault encryption")

	reshareCmd.MarkFlagRequired("email")
	reshareCmd.MarkFlagRequired("password")
	reshareCmd.MarkFlagRequired("plugin-id")

	inspectCmd.Flags().StringP("local-password", "l", "", "Local password for vault encryption")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	sessionID, _ := cmd.Flags().GetString("session")
	localPartyID, _ := cmd.Flags().GetString("party")
	relayServer, _ := cmd.Flags().GetString("relay")
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")

	// Generate chain code and encryption key
	hexChainCode, err := utils.GenerateChainCode()
	if err != nil {
		return err
	}

	encryptionKey, err := utils.GenerateEncryptionKey()
	if err != nil {
		return err
	}
	fmt.Printf("Generated encryption key: %s\n", encryptionKey)

	// Get local party ID
	localPartyID, err = utils.GetLocalPartyID(localPartyID)
	if err != nil {
		return err
	}

	// Initialize storage
	localStorage, err := utils.InitializeStorage()
	if err != nil {
		return err
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
	if !utils.AskForConfirmation("Do you want to proceed with vault creation?") {
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

	vaultDir, _ := utils.GetVaultDirectory()
	fmt.Println("\n✅ Vault created successfully!")
	fmt.Printf("Vault Name: %s\n", name)
	fmt.Printf("ECDSA Public Key: %s\n", ecdsaKey)
	fmt.Printf("EdDSA Public Key: %s\n", eddsaKey)
	fmt.Printf("Vault saved to: %s\n", vaultDir)

	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	// Initialize storage
	localStorage, err := utils.InitializeStorage()
	if err != nil {
		return err
	}

	// List vaults
	vaults, err := localStorage.ListVaults()
	if err != nil {
		return fmt.Errorf("failed to list vaults: %w", err)
	}

	if len(vaults) == 0 {
		vaultDir, _ := utils.GetVaultDirectory()
		fmt.Println("No vaults found in", vaultDir)
		return nil
	}

	vaultDir, _ := utils.GetVaultDirectory()
	fmt.Printf("Found %d vault(s) in %s:\n\n", len(vaults), vaultDir)
	for i, vault := range vaults {
		fmt.Printf("%d. %s\n", i+1, vault)
	}

	return nil
}

func runInspect(cmd *cobra.Command, args []string) error {
	vaultInput := args[0]
	localPassword, _ := cmd.Flags().GetString("local-password")

	// Initialize storage for vault loading
	localStorage, err := utils.InitializeStorage()
	if err != nil {
		return err
	}

	// Load and parse vault
	vaultLoader := utils.NewVaultLoader(localStorage)
	vault, vaultContainer, vaultPath, err := vaultLoader.LoadAndParseVault(vaultInput, localPassword)
	if err != nil {
		return err
	}

	// Get raw vault data for size information
	vaultData, _, err := vaultLoader.LoadVaultData(vaultInput)
	if err != nil {
		return err
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
	vaultBytes, _ := base64.StdEncoding.DecodeString(vaultContainer.Vault)
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
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	pluginID, _ := cmd.Flags().GetString("plugin-id")
	localPassword, _ := cmd.Flags().GetString("local-password")

	// Initialize storage and load vault
	localStorage, err := utils.InitializeStorage()
	if err != nil {
		return err
	}

	vaultLoader := utils.NewVaultLoader(localStorage)
	vault, _, _, err := vaultLoader.LoadAndParseVault(vaultInput, localPassword)
	if err != nil {
		return err
	}

	// Generate new encryption key for reshare
	encryptionKey, err := utils.GenerateEncryptionKey()
	if err != nil {
		return err
	}

	localParty, err := utils.GetLocalPartyID(localPartyID)
	if err != nil {
		return err
	}

	// Show reshare info
	fmt.Printf("Resharing vault '%s'...\n", vault.Name)
	fmt.Printf("Original Public Key: %s\n", vault.PublicKeyEcdsa)
	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("Local Party ID: %s\n", localParty)
	fmt.Printf("Relay Server: %s\n", relayServer)
	fmt.Printf("Verifier Server: %s\n", verifierServer)
	fmt.Printf("Encryption Key: %s\n", encryptionKey)
	fmt.Printf("Email: %s\n", email)
	fmt.Printf("Old Parties: %v\n", vault.Signers)
	fmt.Println()

	// Confirm before proceeding
	if !utils.AskForConfirmation("Do you want to proceed with vault resharing?") {
		fmt.Println("Vault resharing cancelled.")
		return nil
	}

	// Create reshare request
	reshareReq := utils.ReshareRequest{
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
	if err := utils.SendReshareRequests(reshareReq, verifierServer); err != nil {
		return err
	}

	// Wait for all 4 parties to join the session and then start the reshare
	fmt.Println("\nWaiting for all 4 parties to join the reshare session...")

	partiesJoined, err := utils.WaitForPartiesToJoin(sessionID, relayServer, localParty, 4, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to wait for all parties: %w", err)
	}

	// Select all parties except server-*
	newCommittee := []string{}
	for _, party := range partiesJoined {
		if !strings.HasPrefix(strings.ToLower(party), "server-") {
			newCommittee = append(newCommittee, party)
		}
	}

	fmt.Println("\n✅ All 4 parties have joined the reshare session!")
	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("New committee: %v (threshold: 2 of 4)\n", newCommittee)

	// Now start the reshare process as the initiating party
	fmt.Println("\nStarting reshare process...")
	if err := performReshare(vault, sessionID, encryptionKey, relayServer, localParty, newCommittee); err != nil {
		return fmt.Errorf("failed to perform reshare: %w", err)
	}

	fmt.Println("\n✅ Reshare completed successfully!")

	return nil
}

func performReshare(vault *vaultType.Vault, sessionID, encryptionKey, relayServer, localParty string, newCommittee []string) error {
	fmt.Println("📋 Reshare Summary:")
	fmt.Printf("   Old Committee: %v (threshold: %d)\n", vault.Signers, len(vault.Signers))
	fmt.Printf("   New Committee: %v (threshold: 2)\n", newCommittee)
	fmt.Println()

	// Create setup messages and participate in reshare for both key types
	fmt.Println("🔑 Starting ECDSA key reshare...")
	if err := utils.CreateQcSetupAndReshare(vault, sessionID, encryptionKey, localParty, newCommittee, vault.PublicKeyEcdsa, false); err != nil {
		return fmt.Errorf("failed to reshare ECDSA key: %w", err)
	}

	fmt.Println("🔑 Starting EdDSA key reshare...")
	if err := utils.CreateQcSetupAndReshare(vault, sessionID, encryptionKey, localParty, newCommittee, vault.PublicKeyEddsa, true); err != nil {
		return fmt.Errorf("failed to reshare EdDSA key: %w", err)
	}

	fmt.Println("\n✅ Both key reshares completed successfully!")
	fmt.Println("📝 Note: The CLI has successfully created QC setup messages and initiated the reshare.")
	fmt.Println("📝 Note: Other parties (vultiserver, verifier, plugin) will now complete the reshare process.")
	fmt.Println("📝 Note: New vault files with updated keyshares will be saved by each party.")

	return nil
}
