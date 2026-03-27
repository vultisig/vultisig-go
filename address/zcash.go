package address

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
	"golang.org/x/crypto/ripemd160"
)

// ZcashMainNetAddressPrefix is the prefix for transparent P2PKH addresses (t1...).
var ZcashMainNetAddressPrefix = []byte{0x1C, 0xB8}

// GetZcashAddress generates a Zcash transparent P2PKH address from a hex-encoded public key.
func GetZcashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	h := hash160(pubKeyBytes)
	data := make([]byte, len(ZcashMainNetAddressPrefix)+len(h))
	copy(data, ZcashMainNetAddressPrefix)
	copy(data[len(ZcashMainNetAddressPrefix):], h)
	return encoding.Base58CheckEncode(data), nil
}

// hash160 computes RIPEMD160(SHA256(data)).
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(sha[:])
	return r.Sum(nil)
}

// base58CheckEncode is a package-local alias for use within this package.
func base58CheckEncode(data []byte) string {
	return encoding.Base58CheckEncode(data)
}

// base58Encode is a package-local alias for use within this package.
func base58Encode(data []byte) string {
	return encoding.Base58Encode(data)
}
