package address

import (
	"fmt"

	"github.com/vultisig/vultisig-go/encoding/ss58"
)

// SS58Encode encodes data and format identifier to an SS58 checksummed string.
func SS58Encode(pubkey []byte, format uint16) (string, error) {
	result, err := ss58.SS58Encode(pubkey, format)
	if err != nil {
		return "", fmt.Errorf("ss58 encode: %w", err)
	}
	return result, nil
}
