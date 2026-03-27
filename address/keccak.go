package address

import "github.com/vultisig/vultisig-go/encoding"

// keccak256 delegates to encoding.Keccak256 for use within this package.
func keccak256(data []byte) [32]byte {
	return encoding.Keccak256(data)
}
