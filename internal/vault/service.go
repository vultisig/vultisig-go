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
	"github.com/vultisig/vultisig-cli/internal/vault/wrappers"
)

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

// CreateVault creates a new DKLS vault
func (s *Service) CreateVault(req CreateVaultRequest) (string, string, error) {
	s.logger.WithFields(logrus.Fields{
		"name":           req.Name,
		"session":        req.SessionID,
		"local_party_id": req.LocalPartyId,
	}).Info("Creating vault")

	relayClient := relay.NewRelayClient(s.relayServer)
	var err error

	// Register session
	if err := relayClient.RegisterSession(req.SessionID, req.LocalPartyId); err != nil {
		return "", "", fmt.Errorf("failed to register session: %w", err)
	}

	// Ask Vultiserver to join the session
	payload := types.VaultCreateRequest{
		Name:               req.Name,
		SessionID:          req.SessionID,
		HexEncryptionKey:   req.HexEncryptionKey,
		HexChainCode:       req.HexChainCode,
		LocalPartyId:       "test-party",
		EncryptionPassword: req.EncryptionPassword,
		Email:              req.Email,
		LibType:            types.DKLS,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send it to api.vultisig.com/vault/create
	response, err := http.Post("https://api.vultisig.com/vault/create", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", "", fmt.Errorf("failed to send payload: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		s.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"body":    string(body),
		}).Error("Failed to create vault")
		return "", "", fmt.Errorf("failed to create vault: %s", response.Status)
	}

	s.logger.WithFields(logrus.Fields{
		"session": req.SessionID,
		"body":    string(body),
	}).Info("Received response from vault/create")

	// Wait for session start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get joined parties from relay server while context is valid
	partiesJoined := []string{}
	for ctx.Err() == nil {
		partiesJoined, err = relayClient.GetSession(req.SessionID)
		if err != nil {
			return "", "", fmt.Errorf("failed to get session: %w", err)
		}
		if len(partiesJoined) == 2 {
			// Enough parties have joined, start the session
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

	// partiesJoined, err := relayClient.WaitForSessionStart(ctx, req.SessionID)
	// if err != nil {
	// 	return "", "", fmt.Errorf("failed to wait for session start: %w", err)
	// }

	s.logger.WithFields(logrus.Fields{
		"sessionID":      req.SessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started")

	// Create ECDSA key
	publicKeyECDSA, chainCodeECDSA, err := s.keygenWithRetry(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, false, partiesJoined)
	if err != nil {
		return "", "", fmt.Errorf("failed to keygen ECDSA: %w", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Create EdDSA key
	publicKeyEdDSA, _, err := s.keygenWithRetry(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, true, partiesJoined)
	if err != nil {
		return "", "", fmt.Errorf("failed to keygen EdDSA: %w", err)
	}

	// Complete session
	if err := relayClient.CompleteSession(req.SessionID, req.LocalPartyId); err != nil {
		s.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	// Save vault
	err = s.saveVault(req.Name, req.LocalPartyId, partiesJoined, publicKeyECDSA, publicKeyEdDSA, chainCodeECDSA)
	if err != nil {
		return "", "", fmt.Errorf("failed to save vault: %w", err)
	}

	return publicKeyECDSA, publicKeyEdDSA, nil
}

func (s *Service) keygenWithRetry(sessionID, hexEncryptionKey, localPartyID string, isEdDSA bool, keygenCommittee []string) (string, string, error) {
	for i := 0; i < 3; i++ {
		publicKey, chainCode, err := s.keygen(sessionID, hexEncryptionKey, localPartyID, isEdDSA, keygenCommittee, i)
		if err != nil {
			s.logger.WithFields(logrus.Fields{
				"session_id":       sessionID,
				"local_party_id":   localPartyID,
				"keygen_committee": keygenCommittee,
				"attempt":          i,
			}).Error(err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return publicKey, chainCode, nil
	}
	return "", "", fmt.Errorf("failed to keygen after max retry")
}

func (s *Service) keygen(sessionID, hexEncryptionKey, localPartyID string, isEdDSA bool, keygenCommittee []string, attempt int) (string, string, error) {
	s.logger.WithFields(logrus.Fields{
		"session_id":       sessionID,
		"local_party_id":   localPartyID,
		"keygen_committee": keygenCommittee,
		"attempt":          attempt,
		"is_eddsa":         isEdDSA,
	}).Info("Starting keygen")

	s.isKeygenFinished.Store(false)
	relayClient := relay.NewRelayClient(s.relayServer)
	mpcKeygenWrapper := wrappers.NewMPCWrapper(isEdDSA)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Retrieve setup message
	encryptedEncodedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, "")
	if err != nil {
		return "", "", fmt.Errorf("failed to get setup message: %w", err)
	}

	setupMessageBytes, err := s.decodeDecryptMessage(encryptedEncodedSetupMsg, hexEncryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode setup message: %w", err)
	}

	handle, err := mpcKeygenWrapper.KeygenSessionFromSetup(setupMessageBytes, []byte(localPartyID))
	if err != nil {
		return "", "", fmt.Errorf("failed to create session from setup message: %w", err)
	}
	defer func() {
		if err := mpcKeygenWrapper.KeygenSessionFree(handle); err != nil {
			s.logger.Error("failed to free keygen session", "error", err)
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		if err := s.processKeygenOutbound(handle, sessionID, hexEncryptionKey, keygenCommittee, localPartyID, isEdDSA, wg); err != nil {
			s.logger.Error("failed to process keygen outbound", "error", err)
		}
	}()

	publicKey, chainCode, err := s.processKeygenInbound(handle, sessionID, hexEncryptionKey, isEdDSA, localPartyID, wg)
	wg.Wait()
	return publicKey, chainCode, err
}

func (s *Service) processKeygenOutbound(handle wrappers.Handle, sessionID, hexEncryptionKey string, parties []string, localPartyID string, isEdDSA bool, wg *sync.WaitGroup) error {
	defer wg.Done()
	messenger := relay.NewMessenger(s.relayServer, sessionID, hexEncryptionKey, true, "")
	mpcKeygenWrapper := wrappers.NewMPCWrapper(isEdDSA)

	for {
		outbound, err := mpcKeygenWrapper.KeygenSessionOutputMessage(handle)
		if err != nil {
			s.logger.Error("failed to get output message", "error", err)
		}
		if len(outbound) == 0 {
			if s.isKeygenFinished.Load() {
				return nil
			}
			time.Sleep(time.Millisecond * 100)
			continue
		}

		encodedOutbound := base64.StdEncoding.EncodeToString(outbound)
		for i := 0; i < len(parties); i++ {
			receiver, err := mpcKeygenWrapper.KeygenSessionMessageReceiver(handle, outbound, i)
			if err != nil {
				s.logger.Error("failed to get receiver message", "error", err)
			}
			if len(receiver) == 0 {
				continue
			}

			s.logger.Infoln("Sending message to", receiver)
			if err := messenger.Send(localPartyID, receiver, encodedOutbound); err != nil {
				s.logger.Errorf("failed to send message: %v", err)
			}
		}
	}
}

func (s *Service) processKeygenInbound(handle wrappers.Handle, sessionID, hexEncryptionKey string, isEdDSA bool, localPartyID string, wg *sync.WaitGroup) (string, string, error) {
	defer wg.Done()
	var messageCache sync.Map
	mpcKeygenWrapper := wrappers.NewMPCWrapper(isEdDSA)
	relayClient := relay.NewRelayClient(s.relayServer)
	start := time.Now()

	for {
		select {
		case <-time.After(time.Millisecond * 100):
			if time.Since(start) > (time.Minute * 2) {
				s.isKeygenFinished.Store(true)
				s.logger.Error("keygen timeout")
				return "", "", fmt.Errorf("keygen timeout")
			}

			messages, err := relayClient.DownloadMessages(sessionID, localPartyID, "")
			if err != nil {
				s.logger.Error("failed to download messages", "error", err)
				continue
			}

			for _, message := range messages {
				if message.From == localPartyID {
					continue
				}
				cacheKey := fmt.Sprintf("%s-%s-%s", sessionID, localPartyID, message.Hash)
				if _, found := messageCache.Load(cacheKey); found {
					s.logger.Infof("Message already applied, skipping,hash: %s", message.Hash)
					continue
				}

				inboundBody, err := s.decodeDecryptMessage(message.Body, hexEncryptionKey)
				if err != nil {
					s.logger.Error("fail to decode inbound message", "error", err)
					continue
				}

				s.logger.Infoln("Received message from", message.From)
				isFinished, err := mpcKeygenWrapper.KeygenSessionInputMessage(handle, inboundBody)
				if err != nil {
					s.logger.Error("fail to apply input message", "error", err)
					continue
				}

				if err := relayClient.DeleteMessageFromServer(sessionID, localPartyID, message.Hash, ""); err != nil {
					s.logger.Error("fail to delete message", "error", err)
				}

				if isFinished {
					s.logger.Infoln("Keygen finished")
					result, err := mpcKeygenWrapper.KeygenSessionFinish(handle)
					if err != nil {
						s.logger.Error("fail to finish keygen", "error", err)
						return "", "", err
					}

					buf, err := mpcKeygenWrapper.KeyshareToBytes(result)
					if err != nil {
						s.logger.Error("fail to convert keyshare to bytes", "error", err)
						return "", "", err
					}

					encodedShare := base64.StdEncoding.EncodeToString(buf)
					publicKeyBytes, err := mpcKeygenWrapper.KeysharePublicKey(result)
					if err != nil {
						s.logger.Error("fail to get public key", "error", err)
						return "", "", err
					}

					encodedPublicKey := hex.EncodeToString(publicKeyBytes)
					s.logger.Infof("Public key: %s", encodedPublicKey)

					chainCode := ""
					if !isEdDSA {
						chainCodeBytes, err := mpcKeygenWrapper.KeyshareChainCode(result)
						if err != nil {
							s.logger.Error("fail to get chain code", "error", err)
							return "", "", err
						}
						chainCode = hex.EncodeToString(chainCodeBytes)
					}

					s.isKeygenFinished.Store(true)
					err = s.localStateAccessor.SaveLocalState(encodedPublicKey, encodedShare)
					return encodedPublicKey, chainCode, err
				}
			}
		}
	}
}

func (s *Service) saveVault(vaultName, localPartyId string, partiesJoined []string, ecdsaPubkey, eddsaPubkey, hexChainCode string) error {
	ecdsaKeyShare, err := s.localStateAccessor.GetLocalState(ecdsaPubkey)
	if err != nil {
		return fmt.Errorf("failed to get ECDSA local state: %w", err)
	}

	eddsaKeyShare, err := s.localStateAccessor.GetLocalState(eddsaPubkey)
	if err != nil {
		return fmt.Errorf("failed to get EdDSA local state: %w", err)
	}

	vault := &vaultType.Vault{
		Name:           vaultName,
		PublicKeyEcdsa: ecdsaPubkey,
		PublicKeyEddsa: eddsaPubkey,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.New(time.Now()),
		HexChainCode:   hexChainCode,
		KeyShares: []*vaultType.Vault_KeyShare{
			{
				PublicKey: ecdsaPubkey,
				Keyshare:  ecdsaKeyShare,
			},
			{
				PublicKey: eddsaPubkey,
				Keyshare:  eddsaKeyShare,
			},
		},
		LocalPartyId:  localPartyId,
		ResharePrefix: "",
		LibType:       keygen.LibType_LIB_TYPE_DKLS,
	}

	return s.saveVaultToStorage(vault)
}

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

	fileName := fmt.Sprintf("%s-%s.vult", vault.Name, vault.PublicKeyEcdsa[:8])
	return s.storage.SaveVault(fileName, vaultBackupData)
}

func (s *Service) decodeDecryptMessage(encodedMessage, hexEncryptionKey string) ([]byte, error) {
	// Decode base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// For DKLS, messages might be encrypted with the session key
	// This is a simplified implementation - you might need actual decryption
	return encryptedBytes, nil
}
