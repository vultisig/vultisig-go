package cmd

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(createCmd)
	vaultCmd.AddCommand(listCmd)

	// Add flags for vault creation
	createCmd.Flags().StringP("name", "n", "", "Vault name (required)")
	createCmd.Flags().StringP("session", "s", uuid.New().String(), "Session ID (randomly generated if not provided)")
	createCmd.Flags().StringP("party", "p", "", "Local party ID (optional - hostname if not provided)")
	createCmd.Flags().StringP("relay", "r", "https://api.vultisig.com/router/", "Relay server URL")
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
