package address

import (
	"encoding/hex"
	"fmt"
)

func GetBitcoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	witnessProgram := hash160(pubKeyBytes)
	// P2WPKH: witness version 0 + 20-byte keyhash, bech32 encoded with "bc" HRP
	return segwitEncode("bc", 0, witnessProgram)
}

// segwitEncode encodes a segwit address with the given HRP, witness version, and program.
func segwitEncode(hrp string, version byte, program []byte) (string, error) {
	data, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("converting witness program: %w", err)
	}
	// Prepend witness version
	data = append([]int{int(version)}, data...)
	return bech32Encode(hrp, data), nil
}
