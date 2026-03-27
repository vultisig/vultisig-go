package address

import (
	"encoding/hex"
	"fmt"
	"strings"
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
	// Keccak-256 of uncompressed key (without 04 prefix), take last 20 bytes
	hash := keccak256(uncompressed)
	addr := hash[12:]
	return eip55Checksum(addr), nil
}

// eip55Checksum returns EIP-55 mixed-case checksum encoding of an address.
func eip55Checksum(addr []byte) string {
	hexAddr := hex.EncodeToString(addr)
	hash := keccak256([]byte(hexAddr))

	var result strings.Builder
	result.WriteString("0x")
	for i, c := range hexAddr {
		if c >= '0' && c <= '9' {
			result.WriteByte(byte(c))
		} else {
			// Each hex char maps to 4 bits in the hash
			hashByte := hash[i/2]
			var nibble byte
			if i%2 == 0 {
				nibble = hashByte >> 4
			} else {
				nibble = hashByte & 0x0f
			}
			if nibble >= 8 {
				result.WriteByte(byte(c - 32)) // uppercase
			} else {
				result.WriteByte(byte(c))
			}
		}
	}
	return result.String()
}
