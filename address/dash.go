package address

import (
	"encoding/hex"
	"fmt"
)

// Dash mainnet address prefix (1 byte)
var (
	// DashMainNetAddressPrefix is the prefix for P2PKH addresses (X...)
	DashMainNetAddressPrefix = []byte{0x4C}
)

// GetDashAddress generates a Dash P2PKH address from a hex-encoded public key.
// The resulting address starts with "X" for mainnet.
func GetDashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Hash160: RIPEMD160(SHA256(publicKey))
	hash160 := hash160(pubKeyBytes)

	// Encode with Dash prefix (standard Bitcoin-style base58check)
	return encodeDashAddress(DashMainNetAddressPrefix, hash160), nil
}

// encodeDashAddress encodes a hash with prefix to a base58check address
func encodeDashAddress(prefix []byte, hash []byte) string {
	// Dash uses 1-byte prefix + 20-byte hash (same as Bitcoin)
	data := make([]byte, len(prefix)+len(hash))
	copy(data, prefix)
	copy(data[len(prefix):], hash)
	return base58CheckEncode(data)
}
