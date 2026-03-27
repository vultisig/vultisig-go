package address

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// secp256k1 curve parameters
var (
	secp256k1N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// getDerivedPubKey derives a child public key from a parent public key using BIP-32 derivation.
// This replaces mobile-tss-lib's tss.GetDerivedPubKey for ECDSA keys.
func getDerivedPubKey(hexPubKey, hexChainCode, path string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key hex: %w", err)
	}

	chainCode, err := hex.DecodeString(hexChainCode)
	if err != nil {
		return "", fmt.Errorf("invalid chain code hex: %w", err)
	}
	if len(chainCode) != 32 {
		return "", fmt.Errorf("chain code must be 32 bytes, got %d", len(chainCode))
	}

	indices, err := parsePath(path)
	if err != nil {
		return "", fmt.Errorf("invalid derivation path: %w", err)
	}

	// Decompress the parent public key to get (x, y)
	x, y, err := decompressPoint(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}

	// Derive through each path component
	curX, curY := x, y
	curChainCode := chainCode
	for _, index := range indices {
		curX, curY, curChainCode, err = deriveChild(curX, curY, curChainCode, index)
		if err != nil {
			return "", fmt.Errorf("derivation failed at index %d: %w", index, err)
		}
	}

	// Compress the derived public key
	compressed := compressPoint(curX, curY)
	return hex.EncodeToString(compressed), nil
}

// parsePath parses a BIP-32 derivation path like "m/84'/0'/0'/0/0".
// In TSS context, all indices are treated as non-hardened regardless of apostrophe.
func parsePath(path string) ([]uint32, error) {
	var indices []uint32
	for _, item := range strings.Split(path, "/") {
		if item == "" || item == "m" {
			continue
		}
		item = strings.TrimSuffix(item, "'")
		val, err := strconv.ParseUint(item, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path component: %w", err)
		}
		indices = append(indices, uint32(val))
	}
	return indices, nil
}

// deriveChild performs one level of BIP-32 public key derivation (non-hardened style).
// In TSS context, all derivations use the public key method regardless of hardened bit.
func deriveChild(parentX, parentY *big.Int, chainCode []byte, index uint32) (*big.Int, *big.Int, []byte, error) {
	// Serialize parent public key (compressed)
	compressed := compressPoint(parentX, parentY)

	// HMAC-SHA512(key=chainCode, data=compressedPubKey || index)
	data := make([]byte, 33+4)
	copy(data, compressed)
	binary.BigEndian.PutUint32(data[33:], index)

	mac := hmac.New(sha512.New, chainCode)
	mac.Write(data)
	I := mac.Sum(nil)

	IL := new(big.Int).SetBytes(I[:32])
	IR := I[32:]

	// IL must be less than curve order
	if IL.Cmp(secp256k1N) >= 0 {
		return nil, nil, nil, fmt.Errorf("derived key is invalid (IL >= N)")
	}

	// childKey = point(IL) + parentKey
	// First compute IL * G (base point multiplication)
	ilGx, ilGy := scalarBaseMult(IL)

	// Then add parent point
	childX, childY := pointAdd(ilGx, ilGy, parentX, parentY)

	// Check for point at infinity
	if childX.Sign() == 0 && childY.Sign() == 0 {
		return nil, nil, nil, fmt.Errorf("derived key is point at infinity")
	}

	return childX, childY, IR, nil
}

// decompressPoint decompresses a 33-byte compressed secp256k1 point.
func decompressPoint(compressed []byte) (*big.Int, *big.Int, error) {
	if len(compressed) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed key length: %d", len(compressed))
	}
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil, fmt.Errorf("invalid prefix: 0x%02x", prefix)
	}

	x := new(big.Int).SetBytes(compressed[1:])

	// y² = x³ + 7 (mod p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, secp256k1P)
	y2 := new(big.Int).Add(x3, secp256k1B)
	y2.Mod(y2, secp256k1P)

	// y = sqrt(y²) mod p using (p+1)/4
	exp := new(big.Int).Add(secp256k1P, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, secp256k1P)

	// Verify
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

// compressPoint compresses a secp256k1 point to 33 bytes.
func compressPoint(x, y *big.Int) []byte {
	result := make([]byte, 33)
	if y.Bit(0) == 0 {
		result[0] = 0x02
	} else {
		result[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(result[33-len(xBytes):], xBytes)
	return result
}

// scalarBaseMult computes k * G on secp256k1.
func scalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return scalarMult(secp256k1Gx, secp256k1Gy, k)
}

// scalarMult computes k * P on secp256k1 using double-and-add.
func scalarMult(px, py, k *big.Int) (*big.Int, *big.Int) {
	rx, ry := new(big.Int), new(big.Int) // point at infinity
	isInfinity := true
	tx, ty := new(big.Int).Set(px), new(big.Int).Set(py)

	kk := new(big.Int).Set(k)
	for kk.Sign() > 0 {
		if kk.Bit(0) == 1 {
			if isInfinity {
				rx.Set(tx)
				ry.Set(ty)
				isInfinity = false
			} else {
				rx, ry = pointAdd(rx, ry, tx, ty)
			}
		}
		tx, ty = pointDouble(tx, ty)
		kk.Rsh(kk, 1)
	}
	return rx, ry
}

// pointAdd adds two points on secp256k1.
func pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return pointDouble(x1, y1)
	}
	if x1.Cmp(x2) == 0 {
		return new(big.Int), new(big.Int) // point at infinity
	}

	// s = (y2 - y1) / (x2 - x1) mod p
	dy := new(big.Int).Sub(y2, y1)
	dy.Mod(dy, secp256k1P)
	dx := new(big.Int).Sub(x2, x1)
	dx.Mod(dx, secp256k1P)
	dxInv := new(big.Int).ModInverse(dx, secp256k1P)
	s := new(big.Int).Mul(dy, dxInv)
	s.Mod(s, secp256k1P)

	// x3 = s² - x1 - x2
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, secp256k1P)

	// y3 = s(x1 - x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, y1)
	y3.Mod(y3, secp256k1P)

	return x3, y3
}

// pointDouble doubles a point on secp256k1.
func pointDouble(x, y *big.Int) (*big.Int, *big.Int) {
	if y.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// s = (3x² + a) / (2y) mod p  (a=0 for secp256k1)
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, secp256k1P)
	num := new(big.Int).Mul(big.NewInt(3), x2)
	num.Mod(num, secp256k1P)

	den := new(big.Int).Mul(big.NewInt(2), y)
	den.Mod(den, secp256k1P)
	denInv := new(big.Int).ModInverse(den, secp256k1P)
	s := new(big.Int).Mul(num, denInv)
	s.Mod(s, secp256k1P)

	// x3 = s² - 2x
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x))
	x3.Mod(x3, secp256k1P)

	// y3 = s(x - x3) - y
	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, y)
	y3.Mod(y3, secp256k1P)

	return x3, y3
}
