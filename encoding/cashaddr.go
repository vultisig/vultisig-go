package encoding

import "fmt"

// CashAddrEncode encodes a Bitcoin Cash address in cashaddr format.
// prefix is typically "bitcoincash". addrType is 0x00 for P2PKH, 0x08 for P2SH.
// hash must be 20, 24, 28, 32, 40, 48, 56, or 64 bytes.
func CashAddrEncode(prefix string, addrType byte, hash []byte) (string, error) {
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

	versionByte := (addrType << 3) | sizeBits
	payload := append([]byte{versionByte}, hash...)
	data := cashAddrConvertBits(payload, 8, 5)
	checksum := cashAddrCreateChecksum(prefix, data)
	data = append(data, checksum...)

	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	result := make([]byte, 0, len(prefix)+1+len(data))
	result = append(result, []byte(prefix)...)
	result = append(result, ':')
	for _, d := range data {
		result = append(result, charset[d])
	}
	return string(result), nil
}

func cashAddrConvertBits(data []byte, fromBits, toBits int) []byte {
	acc, bits := 0, 0
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

func cashAddrCreateChecksum(prefix string, payload []byte) []byte {
	enc := make([]byte, 0, len(prefix)+1+len(payload)+8)
	for _, c := range prefix {
		enc = append(enc, byte(c&0x1f))
	}
	enc = append(enc, 0)
	enc = append(enc, payload...)
	enc = append(enc, 0, 0, 0, 0, 0, 0, 0, 0)

	polymod := cashAddrPolymod(enc)
	checksum := make([]byte, 8)
	for i := 0; i < 8; i++ {
		checksum[i] = byte((polymod >> uint(5*(7-i))) & 0x1f)
	}
	return checksum
}
