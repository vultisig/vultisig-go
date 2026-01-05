package address

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// TronMainNetAddressPrefix is the prefix byte for TRON mainnet addresses (0x41)
const TronMainNetAddressPrefix = byte(0x41)

// GetTronAddress derives a TRON address from a hex-encoded compressed public key.
// TRON addresses use the same derivation as Ethereum (Keccak256 of uncompressed pubkey),
// but encode with base58check using the 0x41 prefix.
//
// Steps:
// 1. Decompress the public key
// 2. Keccak256 hash of uncompressed key (without 04 prefix)
// 3. Take last 20 bytes
// 4. Prefix with 0x41 (mainnet)
// 5. Base58Check encode
func GetTronAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Decompress the public key
	pubKey, err := crypto.DecompressPubkey(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decompress public key: %w", err)
	}

	// Get Ethereum-style address (Keccak256 of uncompressed pubkey, last 20 bytes)
	ethAddr := crypto.PubkeyToAddress(*pubKey)

	// Prepend TRON mainnet prefix (0x41)
	tronAddrBytes := append([]byte{TronMainNetAddressPrefix}, ethAddr.Bytes()...)

	// Base58Check encode
	return base58CheckEncode(tronAddrBytes), nil
}

