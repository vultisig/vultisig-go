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
	if len(compressed) != 33 {
		return nil, fmt.Errorf("invalid compressed key length: %d", len(compressed))
	}
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, fmt.Errorf("invalid compressed key prefix: 0x%02x", prefix)
	}

	x := new(big.Int).SetBytes(compressed[1:])

	// y² = x³ + 7 (mod p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, secp256k1P)

	y2 := new(big.Int).Add(x3, secp256k1B)
	y2.Mod(y2, secp256k1P)

	// y = sqrt(y²) mod p
	// For secp256k1, p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p
	exp := new(big.Int).Add(secp256k1P, big.NewInt(1))
	exp.Rsh(exp, 2) // (p+1)/4
	y := new(big.Int).Exp(y2, exp, secp256k1P)

	// Verify
	check := new(big.Int).Mul(y, y)
	check.Mod(check, secp256k1P)
	if check.Cmp(y2) != 0 {
		return nil, fmt.Errorf("invalid point: not on curve")
	}

	// Choose correct y based on prefix parity
	isOdd := y.Bit(0) == 1
	wantOdd := prefix == 0x03
	if isOdd != wantOdd {
		y.Sub(secp256k1P, y)
	}

	// Return 64-byte uncompressed (x || y), each padded to 32 bytes
	result := make([]byte, 64)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(result[32-len(xBytes):32], xBytes)
	copy(result[64-len(yBytes):64], yBytes)
	return result, nil
}
