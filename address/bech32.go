package address

// bech32ifyAddressBytes is a package-local alias kept for backward compatibility
// with callers inside this package. The real implementation lives in encoding.Bech32EncodeBytes.
// Delegates to avoid duplicating logic.

import "github.com/vultisig/vultisig-go/encoding"

func bech32ifyAddressBytes(hrp string, bs []byte) (string, error) {
	return encoding.Bech32EncodeBytes(hrp, bs)
}

func bech32Encode(hrp string, data []int) string {
	return encoding.Bech32Encode(hrp, data)
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]int, error) {
	return encoding.ConvertBits(data, fromBits, toBits, pad)
}
