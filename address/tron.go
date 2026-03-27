package address

import (
	"encoding/hex"
	"fmt"
)

// TronMainNetAddressPrefix is the prefix byte for TRON mainnet addresses (0x41)
const TronMainNetAddressPrefix = byte(0x41)

// GetTronAddress derives a TRON address from a hex-encoded compressed public key.
func GetTronAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Decompress the public key
	uncompressed, err := decompressSecp256k1(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decompress public key: %w", err)
	}

	// Keccak256 of uncompressed key, take last 20 bytes
	hash := keccak256(uncompressed)
	ethAddr := hash[12:]

	// Prepend TRON mainnet prefix (0x41) and base58check encode
	tronAddrBytes := append([]byte{TronMainNetAddressPrefix}, ethAddr...)
	return base58CheckEncode(tronAddrBytes), nil
}
