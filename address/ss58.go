package address

import "github.com/vultisig/vultisig-go/encoding/ss58"

// SS58Encode encodes data and format identifier to an SS58 checksumed string.
// It is kept for compatibility; see ss58.SS58Encode.
func SS58Encode(pubkey []byte, format uint16) (string, error) {
	return ss58.SS58Encode(pubkey, format)
}
