package address

import (
	"encoding/hex"
	"fmt"
)

func GetLitecoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	witnessProgram := hash160(pubKeyBytes)
	// P2WPKH: witness version 0 + 20-byte keyhash, bech32 with "ltc" HRP
	return segwitEncode("ltc", 0, witnessProgram)
}
