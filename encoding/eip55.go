package encoding

import (
	"encoding/hex"
	"strings"
)

// EIP55Checksum returns the EIP-55 mixed-case checksum encoding of a 20-byte
// Ethereum address, prefixed with "0x".
// See https://eips.ethereum.org/EIPS/eip-55
func EIP55Checksum(addr []byte) string {
	hexAddr := hex.EncodeToString(addr)
	hash := Keccak256([]byte(hexAddr))

	var result strings.Builder
	result.WriteString("0x")
	for i, c := range hexAddr {
		if c >= '0' && c <= '9' {
			result.WriteByte(byte(c))
		} else {
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
