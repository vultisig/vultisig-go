package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/vultiserver/relay"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/vultisig/vultisig-cli/internal/storage"
	"github.com/vultisig/vultisig-cli/internal/types"
)

// KeygenResult represents the result of a DKLS keygen operation
type KeygenResult struct {
	PublicKey string
	ChainCode string
	Keyshare  string
}

// Service provides vault management functionality
type Service struct {
	relayServer        string
	encryptionSecret   string
	storage            *storage.LocalVaultStorage
	logger             *logrus.Logger
	localStateAccessor *LocalStateAccessor
	isKeygenFinished   *atomic.Bool
}

// NewService creates a new vault service
func NewService(relayServer, encryptionSecret string, storage *storage.LocalVaultStorage) *Service {
	return &Service{
		relayServer:        relayServer,
		encryptionSecret:   encryptionSecret,
		storage:            storage,
		logger:             logrus.WithField("service", "vault").Logger,
		localStateAccessor: NewLocalStateAccessor(),
		isKeygenFinished:   &atomic.Bool{},
	}
}

// CreateVaultRequest represents a vault creation request
type CreateVaultRequest struct {
	Name               string
	SessionID          string
	LocalPartyId       string
	HexEncryptionKey   string
	Email              string
	HexChainCode       string
	EncryptionPassword string
}

// CreateVault creates a new DKLS vault following the 2-of-2 fast vault flow
func (s *Service) CreateVault(req CreateVaultRequest) (string, string, error) {
	s.logger.WithFields(logrus.Fields{
		"name":           req.Name,
		"session":        req.SessionID,
		"local_party_id": req.LocalPartyId,
	}).Info("Creating vault")

	// Step 1: Ask Vultiserver to join the session
	if err := s.setupVaultWithServer(req); err != nil {
		return "", "", fmt.Errorf("failed to setup vault with server: %w", err)
	}

	// Step 2: Register session with relay
	relayClient := relay.NewRelayClient(s.relayServer)
	if err := relayClient.RegisterSession(req.SessionID, req.LocalPartyId); err != nil {
		return "", "", fmt.Errorf("failed to register session: %w", err)
	}

	// Step 3: Wait for server to join
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	partiesJoined := []string{}
	var err error
	for ctx.Err() == nil {
		partiesJoined, err = relayClient.GetSession(req.SessionID)
		if err != nil {
			return "", "", fmt.Errorf("failed to get session: %w", err)
		}
		if len(partiesJoined) == 2 {
			// Both parties joined, start the session
			if err := relayClient.StartSession(req.SessionID, partiesJoined); err != nil {
				return "", "", fmt.Errorf("failed to start session: %w", err)
			}
			break
		}
		s.logger.WithFields(logrus.Fields{
			"session":        req.SessionID,
			"parties_joined": partiesJoined,
		}).Info("Waiting for Vultiserver to join")
		time.Sleep(1 * time.Second)
	}

	s.logger.WithFields(logrus.Fields{
		"sessionID":      req.SessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started, beginning keygen")

	// Step 4: Run ECDSA keygen (CLI is always the initiating device)
	ecdsaResult, err := s.runDKLSKeygen(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"public_key": ecdsaResult.PublicKey,
		"chain_code": ecdsaResult.ChainCode,
	}).Info("ECDSA keygen completed")

	// Step 5: Run EdDSA keygen
	eddsaResult, err := s.runDKLSKeygen(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined, true)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate EdDSA key: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"public_key": eddsaResult.PublicKey,
	}).Info("EdDSA keygen completed")

	// Step 6: Save vault
	err = s.saveVaultResults(req.Name, req.LocalPartyId, partiesJoined, ecdsaResult, eddsaResult)
	if err != nil {
		return "", "", fmt.Errorf("failed to save vault: %w", err)
	}

	return ecdsaResult.PublicKey, eddsaResult.PublicKey, nil
}

// setupVaultWithServer sends the vault creation request to the Vultisig server
func (s *Service) setupVaultWithServer(req CreateVaultRequest) error {
	payload := types.VaultCreateRequest{
		Name:               req.Name,
		SessionID:          req.SessionID,
		HexEncryptionKey:   req.HexEncryptionKey,
		HexChainCode:       req.HexChainCode,
		LocalPartyId:       "server-1234", // Server will use this as its party ID
		EncryptionPassword: req.EncryptionPassword,
		Email:              req.Email,
		LibType:            types.DKLS,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	response, err := http.Post("https://api.vultisig.com/vault/create", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send request to server: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		s.logger.WithFields(logrus.Fields{
			"status": response.StatusCode,
			"body":   string(body),
		}).Error("Server rejected vault creation request")
		return fmt.Errorf("server rejected request: %s", response.Status)
	}

	s.logger.WithFields(logrus.Fields{
		"session": req.SessionID,
		"body":    string(body),
	}).Info("Server accepted vault creation request")

	return nil
}

// runDKLSKeygen runs a complete DKLS keygen operation for either ECDSA or EdDSA
func (s *Service) runDKLSKeygen(sessionID, hexEncryptionKey, localPartyID string, parties []string, isEdDSA bool) (*KeygenResult, error) {
	keygenType := "ECDSA"
	if isEdDSA {
		keygenType = "EdDSA"
	}

	s.logger.WithFields(logrus.Fields{
		"session":  sessionID,
		"key_type": keygenType,
		"parties":  parties,
		"is_eddsa": isEdDSA,
	}).Info("Starting DKLS keygen")

	// Create MPC wrapper for this key type
	mpcWrapper := NewMPCWrapperImp(isEdDSA)

	// Calculate threshold (for 2 parties, threshold should be 2 for 2-of-2)
	threshold := getKeygenThreshold(len(parties))

	// Create setup message using the MPC wrapper
	// Use nil keyID as per go-wrappers test patterns
	var keyID []byte = nil

	// Convert party IDs to bytes format expected by go-wrappers
	// Must be null-separated string as per go-wrappers test patterns
	idsBytes := []byte(strings.Join(parties, "\x00"))

	s.logger.WithFields(logrus.Fields{
		"parties":       parties,
		"ids_bytes_len": len(idsBytes),
		"threshold":     threshold,
	}).Debug("Formatted party IDs for setup message")

	setupMessage, err := mpcWrapper.KeygenSetupMsgNew(threshold, keyID, idsBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create setup message: %w", err)
	}

	// Encrypt and upload setup message
	encryptedSetup, err := s.encodeEncryptMessage(setupMessage, hexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt setup message: %w", err)
	}

	relayClient := relay.NewRelayClient(s.relayServer)
	if err := relayClient.UploadSetupMessage(sessionID, encryptedSetup); err != nil {
		return nil, fmt.Errorf("failed to upload setup message: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"session":  sessionID,
		"key_type": keygenType,
		"size":     len(setupMessage),
	}).Info("Uploaded setup message")

	// Create keygen session from our own setup message
	handle, err := mpcWrapper.KeygenSessionFromSetup(setupMessage, []byte(localPartyID))
	if err != nil {
		return nil, fmt.Errorf("failed to create keygen session: %w", err)
	}

	defer func() {
		if err := mpcWrapper.KeygenSessionFree(handle); err != nil {
			s.logger.WithError(err).Error("Failed to free keygen session")
		}
	}()

	// Run the keygen protocol
	result, err := s.runKeygenProtocol(mpcWrapper, handle, sessionID, hexEncryptionKey, localPartyID)
	if err != nil {
		return nil, fmt.Errorf("keygen protocol failed: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"session":    sessionID,
		"key_type":   keygenType,
		"public_key": result.PublicKey,
	}).Info("DKLS keygen completed successfully")

	return result, nil
}

// getKeygenThreshold calculates the threshold for the given number of signers
func getKeygenThreshold(signers int) int {
	// This follows the formula: Math.ceil((signers * 2) / 3) from vultisig-windows
	// For 2 signers: ceil((2 * 2) / 3) = ceil(4/3) = ceil(1.33) = 2
	// For 2-of-2 fast vault, we use threshold = 2
	if signers == 2 {
		return 2
	}
	return (signers*2 + 2) / 3 // Integer ceiling division
}

// runKeygenProtocol runs the actual keygen protocol with message passing
func (s *Service) runKeygenProtocol(mpcWrapper MPCKeygenWrapper, handle Handle, sessionID, hexEncryptionKey, localPartyID string) (*KeygenResult, error) {
	s.isKeygenFinished.Store(false)
	relayClient := relay.NewRelayClient(s.relayServer)

	// Start outbound and inbound processing concurrently
	errChan := make(chan error, 2)
	resultChan := make(chan *KeygenResult, 1)

	// Process outbound messages
	go func() {
		errChan <- s.processKeygenOutbound(mpcWrapper, handle, sessionID, hexEncryptionKey, localPartyID)
	}()

	// Process inbound messages
	go func() {
		result, err := s.processKeygenInbound(mpcWrapper, handle, sessionID, hexEncryptionKey, localPartyID, relayClient)
		if err != nil {
			errChan <- err
		} else {
			resultChan <- result
		}
	}()

	// Wait for completion or error
	select {
	case result := <-resultChan:
		s.isKeygenFinished.Store(true)
		return result, nil
	case err := <-errChan:
		s.isKeygenFinished.Store(true)
		return nil, err
	case <-time.After(2 * time.Minute):
		s.isKeygenFinished.Store(true)
		return nil, fmt.Errorf("keygen timeout")
	}
}

// processKeygenOutbound handles outbound message processing for keygen
func (s *Service) processKeygenOutbound(mpcWrapper MPCKeygenWrapper, handle Handle, sessionID, hexEncryptionKey, localPartyID string) error {
	messenger := relay.NewMessenger(s.relayServer, sessionID, hexEncryptionKey, true, "")

	for {
		if s.isKeygenFinished.Load() {
			s.logger.Info("Keygen finished, stopping outbound processing")
			return nil
		}

		// Get output message using the MPC wrapper
		outbound, err := mpcWrapper.KeygenSessionOutputMessage(handle)
		if err != nil {
			s.logger.WithError(err).Debug("Failed to get output message")
			continue
		}

		if len(outbound) == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Get message receivers for each outbound message using MPC wrapper
		numReceivers := 2 // For 2-of-2 fast vault

		// Send to each receiver
		for idx := 0; idx < numReceivers; idx++ {
			receiver, err := mpcWrapper.KeygenSessionMessageReceiver(handle, outbound, idx)
			if err != nil {
				s.logger.WithError(err).WithField("receiver_idx", idx).Error("Failed to get message receiver")
				continue
			}
			if receiver == "" || receiver == localPartyID {
				continue // No receiver or self-message
			}

			// Encode message to base64 (messenger handles encryption)
			encodedMessage := base64.StdEncoding.EncodeToString(outbound)

			if err := messenger.Send(localPartyID, receiver, encodedMessage); err != nil {
				s.logger.WithError(err).WithFields(logrus.Fields{
					"receiver": receiver,
					"idx":      idx,
				}).Error("Failed to send message to relay")
			} else {
				s.logger.WithFields(logrus.Fields{
					"session": sessionID,
					"to":      receiver,
					"idx":     idx,
				}).Debug("Sent outbound message")
			}
		}

		time.Sleep(50 * time.Millisecond) // Small delay between sends
	}
}

// processKeygenInbound handles inbound message processing for keygen
func (s *Service) processKeygenInbound(mpcWrapper MPCKeygenWrapper, handle Handle, sessionID, hexEncryptionKey, localPartyID string, relayClient *relay.Client) (*KeygenResult, error) {
	var messageCache sync.Map
	start := time.Now()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(start) > (2 * time.Minute) {
				return nil, fmt.Errorf("keygen timeout")
			}

			messages, err := relayClient.DownloadMessages(sessionID, localPartyID, "")
			if err != nil {
				s.logger.WithError(err).Error("Failed to download messages")
				continue
			}

			for _, message := range messages {
				if message.From == localPartyID {
					continue // Skip our own messages
				}

				cacheKey := fmt.Sprintf("%s-%s-%s", sessionID, localPartyID, message.Hash)
				if _, found := messageCache.Load(cacheKey); found {
					continue // Already processed
				}

				// Decrypt the message
				inboundBody, err := s.decodeDecryptMessage(message.Body, hexEncryptionKey)
				if err != nil {
					s.logger.WithError(err).Error("Failed to decrypt inbound message")
					continue
				}

				s.logger.WithFields(logrus.Fields{
					"from":         message.From,
					"session":      sessionID,
					"message_hash": message.Hash,
				}).Debug("Processing inbound message")

				// Apply message to keygen session using MPC wrapper
				isFinished, err := mpcWrapper.KeygenSessionInputMessage(handle, inboundBody)
				if err != nil {
					s.logger.WithError(err).Error("Failed to apply input message")
					continue
				}

				// Mark message as processed
				messageCache.Store(cacheKey, true)

				// Delete message from server
				if err := relayClient.DeleteMessageFromServer(sessionID, localPartyID, message.Hash, ""); err != nil {
					s.logger.WithError(err).Error("Failed to delete message from server")
				}

				if isFinished {
					s.logger.Info("Keygen completed, finalizing result")

					// Finish the keygen session and extract results
					keyshareResult, err := mpcWrapper.KeygenSessionFinish(handle)
					if err != nil {
						return nil, fmt.Errorf("failed to finish keygen: %w", err)
					}

					// Create a keyshare wrapper to extract data
					keyshareWrapper := mpcWrapper.(MPCKeyshareWrapper) // Safe cast since MPCWrapperImp implements both

					// Extract keyshare bytes, public key, and chain code using MPC wrapper
					keyshareBytes, err := keyshareWrapper.KeyshareToBytes(keyshareResult)
					if err != nil {
						return nil, fmt.Errorf("failed to convert keyshare to bytes: %w", err)
					}

					publicKeyBytes, err := keyshareWrapper.KeysharePublicKey(keyshareResult)
					if err != nil {
						return nil, fmt.Errorf("failed to get public key: %w", err)
					}

					chainCodeBytes, err := keyshareWrapper.KeyshareChainCode(keyshareResult)
					if err != nil {
						s.logger.WithError(err).Warn("Failed to get chain code, continuing without it")
					}

					result := &KeygenResult{
						PublicKey: hex.EncodeToString(publicKeyBytes),
						Keyshare:  base64.StdEncoding.EncodeToString(keyshareBytes),
					}

					// Add chain code for ECDSA keys
					if chainCodeBytes != nil {
						result.ChainCode = hex.EncodeToString(chainCodeBytes)
					}

					// Save to local state
					if err := s.localStateAccessor.SaveLocalState(result.PublicKey, result.Keyshare); err != nil {
						s.logger.WithError(err).Error("Failed to save local state")
					}

					return result, nil
				}
			}
		}
	}
}

// Removed old saveVault method - now using saveVaultResults

func (s *Service) saveVaultToStorage(vault *vaultType.Vault) error {
	if len(s.encryptionSecret) == 0 {
		return fmt.Errorf("encryption secret is empty")
	}

	vaultData, err := proto.Marshal(vault)
	if err != nil {
		return fmt.Errorf("failed to marshal vault: %w", err)
	}

	// For simplicity, we'll store the vault without additional encryption in CLI mode
	// In production, you might want to add client-side encryption

	vaultBackup := &vaultType.VaultContainer{
		Version:     1,
		Vault:       base64.StdEncoding.EncodeToString(vaultData),
		IsEncrypted: false,
	}

	vaultBackupData, err := proto.Marshal(vaultBackup)
	if err != nil {
		return fmt.Errorf("failed to marshal vault backup: %w", err)
	}

	// Encode the protobuf data as base64 to match vultisig-windows format
	base64VaultData := base64.StdEncoding.EncodeToString(vaultBackupData)

	fileName := fmt.Sprintf("%s-%s.vult", vault.Name, vault.PublicKeyEcdsa[:8])
	return s.storage.SaveVault(fileName, []byte(base64VaultData))
}

// Removed old generateAndSendSetupMessages method - now handled in runDKLSKeygen

// encodeEncryptMessage encrypts and encodes a message using AES-GCM
// This follows the same pattern as verifier/common/utils.go
func (s *Service) encodeEncryptMessage(message []byte, hexEncryptionKey string) (string, error) {
	// First base64 encode the message
	base64EncodedMessage := base64.StdEncoding.EncodeToString(message)

	// Then encrypt using AES-GCM
	encryptedMessage, err := EncryptGCM(base64EncodedMessage, hexEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	return encryptedMessage, nil
}

// decodeDecryptMessage decodes and decrypts a message using AES-GCM
// This follows the same pattern as verifier/vault/reshare.go decodeDecryptMessage
func (s *Service) decodeDecryptMessage(encodedMessage, hexEncryptionKey string) ([]byte, error) {
	// First decode from base64
	encryptedMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Decrypt using AES-GCM
	decryptedMessage, err := DecryptGCM(encryptedMessage, hexEncryptionKey)
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

// saveVaultResults saves the keygen results to a vault file
func (s *Service) saveVaultResults(vaultName, localPartyId string, partiesJoined []string, ecdsaResult, eddsaResult *KeygenResult) error {
	vault := &vaultType.Vault{
		Name:           vaultName,
		PublicKeyEcdsa: ecdsaResult.PublicKey,
		PublicKeyEddsa: eddsaResult.PublicKey,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.New(time.Now()),
		HexChainCode:   ecdsaResult.ChainCode,
		KeyShares: []*vaultType.Vault_KeyShare{
			{
				PublicKey: ecdsaResult.PublicKey,
				Keyshare:  ecdsaResult.Keyshare,
			},
			{
				PublicKey: eddsaResult.PublicKey,
				Keyshare:  eddsaResult.Keyshare,
			},
		},
		LocalPartyId:  localPartyId,
		ResharePrefix: "",
		LibType:       keygen.LibType_LIB_TYPE_DKLS,
	}

	return s.saveVaultToStorage(vault)
}
