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
	uncompressed, err := decompressSecp256k1(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decompress public key: %w", err)
	}
	hash := keccak256(uncompressed)
	return encoding.EIP55Checksum(hash[12:]), nil
}
