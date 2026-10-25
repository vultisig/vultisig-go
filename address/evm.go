package address

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

func GetEVMAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	addr, err := keccakAddress(pubKeyBytes)
	if err != nil {
		return "", err
	}
	return encoding.EIP55Checksum(addr), nil
}
