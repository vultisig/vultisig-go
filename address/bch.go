package address

import (
	"encoding/hex"
	"fmt"
)

func GetBitcoinCashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	pubKeyHash := hash160(pubKeyBytes)
	// BCH uses cashaddr format: P2PKH type (0x00) + 20-byte hash
	// EncodeAddress returns without the "bitcoincash:" prefix
	addr, err := cashAddrEncode("bitcoincash", 0x00, pubKeyHash)
	if err != nil {
		return "", err
	}
	// Strip "bitcoincash:" prefix to match standard EncodeAddress behavior
	return addr[len("bitcoincash:"):], nil
}

// cashAddrEncode encodes a Bitcoin Cash address in cashaddr format.
func cashAddrEncode(prefix string, addrType byte, hash []byte) (string, error) {
	// Size bits for 20-byte hash = 0
	var sizeBits byte
	switch len(hash) {
	case 20:
		sizeBits = 0
	case 24:
		sizeBits = 1
	case 28:
		sizeBits = 2
	case 32:
		sizeBits = 3
	case 40:
		sizeBits = 4
	case 48:
		sizeBits = 5
	case 56:
		sizeBits = 6
	case 64:
		sizeBits = 7
	default:
		return "", fmt.Errorf("invalid hash length: %d", len(hash))
	}

	// Version byte: type (upper 4 bits) + size (lower 4 bits)
	versionByte := (addrType << 3) | sizeBits
	payload := append([]byte{versionByte}, hash...)

	// Convert to 5-bit groups
	data := cashAddrConvertBits(payload, 8, 5)

	// Create checksum
	checksum := cashAddrCreateChecksum(prefix, data)
	data = append(data, checksum...)

	// Encode
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	result := make([]byte, 0, len(prefix)+1+len(data))
	result = append(result, []byte(prefix)...)
	result = append(result, ':')
	for _, d := range data {
		result = append(result, charset[d])
	}
	return string(result), nil
}

// cashAddrConvertBits converts data between bit groups.
func cashAddrConvertBits(data []byte, fromBits, toBits int) []byte {
	acc := 0
	bits := 0
	maxv := (1 << toBits) - 1
	var ret []byte
	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if bits > 0 {
		ret = append(ret, byte((acc<<(toBits-bits))&maxv))
	}
	return ret
}

// cashAddrPolymod computes the cashaddr polymod checksum.
func cashAddrPolymod(values []byte) uint64 {
	c := uint64(1)
	for _, d := range values {
		c0 := c >> 35
		c = ((c & 0x07ffffffff) << 5) ^ uint64(d)
		if c0&0x01 != 0 {
			c ^= 0x98f2bc8e61
		}
		if c0&0x02 != 0 {
			c ^= 0x79b76d99e2
		}
		if c0&0x04 != 0 {
			c ^= 0xf33e5fb3c4
		}
		if c0&0x08 != 0 {
			c ^= 0xae2eabe2a8
		}
		if c0&0x10 != 0 {
			c ^= 0x1e4f43e470
		}
	}
	return c ^ 1
}

// cashAddrCreateChecksum creates the 8-byte checksum for a cashaddr.
func cashAddrCreateChecksum(prefix string, payload []byte) []byte {
	// prefix expansion
	enc := make([]byte, 0, len(prefix)+1+len(payload)+8)
	for _, c := range prefix {
		enc = append(enc, byte(c&0x1f))
	}
	enc = append(enc, 0) // separator
	enc = append(enc, payload...)
	// 8 zero bytes for checksum
	enc = append(enc, 0, 0, 0, 0, 0, 0, 0, 0)

	polymod := cashAddrPolymod(enc)
	checksum := make([]byte, 8)
	for i := 0; i < 8; i++ {
		checksum[i] = byte((polymod >> uint(5*(7-i))) & 0x1f)
	}
	return checksum
}
