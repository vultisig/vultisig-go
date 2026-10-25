package address

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

// Zcash mainnet address prefixes (2 bytes)
var (
	// ZcashMainNetAddressPrefix is the prefix for transparent P2PKH addresses (t1...)
	ZcashMainNetAddressPrefix = []byte{0x1C, 0xB8}
)

// GetZcashAddress generates a Zcash transparent P2PKH address from a hex-encoded public key.
// The resulting address starts with "t1" for mainnet.
func GetZcashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Hash160: RIPEMD160(SHA256(publicKey))
	hash160 := hash160(pubKeyBytes)

	// Encode with Zcash prefix
	return encodeZcashAddress(ZcashMainNetAddressPrefix, hash160), nil
}

// encodeZcashAddress encodes a hash with prefix to a base58check address
func encodeZcashAddress(prefix []byte, hash []byte) string {
	// Zcash uses 2-byte prefix + 20-byte hash
	data := make([]byte, len(prefix)+len(hash))
	copy(data, prefix)
	copy(data[len(prefix):], hash)
	return encoding.Base58CheckEncode(data)
}
