package utils

import (
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultisig-go/internal/protocol"
)

// ReshareRequest re-exports the protocol ReshareRequest for compatibility
type ReshareRequest = protocol.ReshareRequest

// SendReshareRequests re-exports the protocol function for compatibility
func SendReshareRequests(req ReshareRequest, verifierServer, pluginServer string) error {
	return protocol.SendReshareRequests(req, verifierServer, pluginServer)
}

// CreateQcSetupAndReshare re-exports the protocol function for compatibility
func CreateQcSetupAndReshare(v *vaultType.Vault, sessionID, encryptionKey, localParty string, newCommittee []string, publicKey string, isEdDSA bool) error {
	return protocol.CreateQcSetupAndReshare(v, sessionID, encryptionKey, localParty, newCommittee, publicKey, isEdDSA)
}
