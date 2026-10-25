package address

import (
	"fmt"
	"math/big"

	"github.com/vultisig/vultisig-go/encoding"
)

// secp256k1 curve parameters: y² = x³ + 7 over the field p.
var (
	secp256k1P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1B    = big.NewInt(7)
)

// decompressPoint decodes a 33-byte compressed secp256k1 public key into
// its affine coordinates, rejecting encodings that are not on the curve.
func decompressPoint(compressed []byte) (*big.Int, *big.Int, error) {
	if len(compressed) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed key length: %d", len(compressed))
	}
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil, fmt.Errorf("invalid prefix: 0x%02x", prefix)
	}

	x := new(big.Int).SetBytes(compressed[1:])
	if x.Cmp(secp256k1P) >= 0 {
		return nil, nil, fmt.Errorf("x coordinate out of range")
	}

	// y² = x³ + 7 (mod p)
	y2 := new(big.Int).Exp(x, big.NewInt(3), secp256k1P)
	y2.Add(y2, secp256k1B)
	y2.Mod(y2, secp256k1P)

	// p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) when a is a square.
	exp := new(big.Int).Add(secp256k1P, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, secp256k1P)

	check := new(big.Int).Mul(y, y)
	check.Mod(check, secp256k1P)
	if check.Cmp(y2) != 0 {
		return nil, nil, fmt.Errorf("point not on curve")
	}

	if y.Bit(0) != uint(prefix&1) {
		y.Sub(secp256k1P, y)
	}
	return x, y, nil
}

// decompressSecp256k1 returns the 64-byte uncompressed form (x || y,
// without the 0x04 prefix) of a 33-byte compressed public key.
func decompressSecp256k1(compressed []byte) ([]byte, error) {
	x, y, err := decompressPoint(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress failed: %w", err)
	}
	result := make([]byte, 64)
	x.FillBytes(result[:32])
	y.FillBytes(result[32:])
	return result, nil
}

// keccakAddress returns the 20-byte Ethereum-style account address of a
// compressed secp256k1 public key: the last 20 bytes of Keccak-256 over
// the uncompressed key.
func keccakAddress(compressed []byte) ([]byte, error) {
	uncompressed, err := decompressSecp256k1(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress public key: %w", err)
	}
	hash := encoding.Keccak256(uncompressed)
	return hash[12:], nil
}
