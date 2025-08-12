package utils

import (
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultisig-go/internal/protocol"
	"github.com/vultisig/vultisig-go/types"
)

// ReshareRequest re-exports the root types ReshareRequest for compatibility
type ReshareRequest = types.ReshareRequest

// SendReshareRequests re-exports the protocol function for compatibility
func SendReshareRequests(req ReshareRequest, verifierServer string) error {
	return protocol.SendReshareRequests(req, verifierServer)
}

// CreateQcSetupAndReshare re-exports the protocol function for compatibility
func CreateQcSetupAndReshare(v *vaultType.Vault, sessionID, encryptionKey, localParty string, newCommittee []string, publicKey string, isEdDSA bool) error {
	return protocol.CreateQcSetupAndReshare(v, sessionID, encryptionKey, localParty, newCommittee, publicKey, isEdDSA)
}
