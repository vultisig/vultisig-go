package address

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

// Zcash mainnet address prefixes (2 bytes)
var (
	// ZcashMainNetAddressPrefix is the prefix for transparent P2PKH addresses (t1...)
	ZcashMainNetAddressPrefix = []byte{0x1C, 0xB8}
)

// GetZcashAddress generates a Zcash transparent P2PKH address from a hex-encoded public key.
// The resulting address starts with "t1" for mainnet.
func GetZcashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Hash160: RIPEMD160(SHA256(publicKey))
	hash160 := hash160(pubKeyBytes)

	// Encode with Zcash prefix
	return encodeZcashAddress(ZcashMainNetAddressPrefix, hash160), nil
}

// hash160 computes RIPEMD160(SHA256(data))
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// encodeZcashAddress encodes a hash with prefix to a base58check address
func encodeZcashAddress(prefix []byte, hash []byte) string {
	// Zcash uses 2-byte prefix + 20-byte hash
	data := make([]byte, len(prefix)+len(hash))
	copy(data, prefix)
	copy(data[len(prefix):], hash)
	return base58CheckEncode(data)
}

// base58CheckEncode encodes data to base58check format
func base58CheckEncode(data []byte) string {
	// Add 4-byte checksum (double SHA256)
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	checksum := second[:4]

	// Create payload with checksum
	payload := make([]byte, len(data)+4)
	copy(payload, data)
	copy(payload[len(data):], checksum)

	// Base58 encode
	return base58Encode(payload)
}

// base58Encode encodes bytes to base58
func base58Encode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros
	var zeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		zeros++
	}

	// Convert to big integer
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	mod := new(big.Int)

	var result []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		result = append([]byte{alphabet[mod.Int64()]}, result...)
	}

	// Add leading 1s for zeros
	for i := 0; i < zeros; i++ {
		result = append([]byte{'1'}, result...)
	}

	return string(result)
}

