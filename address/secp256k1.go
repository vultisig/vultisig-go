package address

import (
	"fmt"
	"math/big"
)

// secp256k1 curve parameters
var (
	secp256k1P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1B    = big.NewInt(7)
)

// decompressSecp256k1 decompresses a 33-byte compressed secp256k1 public key
// to a 64-byte uncompressed form (x || y), without the 0x04 prefix.
func decompressSecp256k1(compressed []byte) ([]byte, error) {
	x, y, err := decompressPoint(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress failed: %w", err)
	}
	result := make([]byte, 64)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(result[32-len(xBytes):32], xBytes)
	copy(result[64-len(yBytes):64], yBytes)
	return result, nil
}
