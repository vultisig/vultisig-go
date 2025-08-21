package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/vultiserver/relay"

	"github.com/vultisig/vultisig-go/common"
	"github.com/vultisig/vultisig-go/internal/vault"
	"github.com/vultisig/vultisig-go/types"
)

// ReshareRequest is an alias to the root types.ReshareRequest for compatibility
type ReshareRequest = types.ReshareRequest

// SendReshareRequests sends reshare requests to all required servers
func SendReshareRequests(req ReshareRequest, verifierServer string) error {
	// Send to vultiserver
	if err := sendJSONRequest("https://api.vultisig.com/vault/reshare", req); err != nil {
		return fmt.Errorf("failed to initiate reshare with vultiserver: %w", err)
	}
	fmt.Println("✓ Vultiserver notified")

	// Send to verifier
	if err := sendJSONRequest(verifierServer+"/vault/reshare", req); err != nil {
		return fmt.Errorf("failed to initiate reshare with verifier: %w", err)
	}
	fmt.Println("✓ Verifier notified")

	return nil
}

// CreateQcSetupAndReshare handles the QC setup and reshare process for a single key type
func CreateQcSetupAndReshare(v *vaultType.Vault, sessionID, encryptionKey, localParty string, newCommittee []string, publicKey string, isEdDSA bool) error {
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

	if err := relayClient.UploadSetupMessage(sessionID, encryptedSetup, eddsaHeader); err != nil {
		return fmt.Errorf("failed to upload setup message: %w", err)
	}

	fmt.Printf("   ✅ Uploaded %s QC setup message to relay\n", keyType)

	// Now create QC session and participate in the reshare protocol
	handle, err := mpcWrapper.QcSessionFromSetup(setupMsg, localParty, keyshareHandle)
	if err != nil {
		return fmt.Errorf("failed to create QC session: %w", err)
	}

	// Run the actual reshare protocol
	fmt.Printf("   🔄 Starting %s reshare protocol...\n", keyType)
	newPublicKey, chainCode, err := RunQcReshareProtocol(mpcWrapper, handle, sessionID, encryptionKey, localParty, newCommittee)
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

// RunQcReshareProtocol runs the QC reshare protocol
func RunQcReshareProtocol(mpcWrapper *vault.MPCWrapperImp, handle vault.Handle, sessionID, encryptionKey, localParty string, committee []string) (string, string, error) {
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
		errChan <- ProcessQcReshareOutbound(mpcWrapper, handle, sessionID, encryptionKey, localParty, committee, isReshareFinished)
	}()

	// Process inbound messages
	go func() {
		publicKey, chainCode, err := ProcessQcReshareInbound(mpcWrapper, handle, sessionID, encryptionKey, localParty, committee, relayClient, isReshareFinished)
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

// ProcessQcReshareOutbound handles outbound message processing for QC reshare
func ProcessQcReshareOutbound(mpcWrapper *vault.MPCWrapperImp, handle vault.Handle, sessionID, encryptionKey, localParty string, committee []string, isReshareFinished *atomic.Bool) error {
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

// ProcessQcReshareInbound handles inbound message processing for QC reshare
func ProcessQcReshareInbound(mpcWrapper *vault.MPCWrapperImp, handle vault.Handle, sessionID, encryptionKey, localParty string, committee []string, relayClient *relay.Client, isReshareFinished *atomic.Bool) (string, string, error) {
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

// sendJSONRequest sends a JSON POST request to the specified URL
func sendJSONRequest(url string, payload interface{}) error {
	jsonPayload, err := json.Marshal(payload)
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

// combineCommittees merges old and new committee members, removing duplicates
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

// getCommitteeIndices returns the indices of old and new committee members in the combined list
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

// encodeEncryptMessage encrypts and encodes a message using AES-GCM
func encodeEncryptMessage(message []byte, hexEncryptionKey string) (string, error) {
	// First base64 encode the message
	base64EncodedMessage := base64.StdEncoding.EncodeToString(message)

	// Then encrypt using AES-GCM
	encryptedMessage, err := common.EncryptGCM(base64EncodedMessage, hexEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	return encryptedMessage, nil
}

// decodeDecryptMessage decodes and decrypts a message using AES-GCM
func decodeDecryptMessage(encodedMessage, hexEncryptionKey string) ([]byte, error) {
	// First decode from base64
	encryptedMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Decrypt using AES-GCM
	decryptedMessage, err := common.DecryptGCM(encryptedMessage, hexEncryptionKey)
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
