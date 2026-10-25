package address

import (
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

// p2wpkhAddress encodes a P2WPKH (witness version 0) address for the
// hash160 of pubKey. Version 0 is bech32; versions 1+ (taproot) need
// bech32m and are not supported.
func p2wpkhAddress(hrp string, pubKey []byte) (string, error) {
	data, err := encoding.ConvertBits(hash160(pubKey), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("converting witness program: %w", err)
	}
	return encoding.Bech32Encode(hrp, append([]int{0}, data...)), nil
}
