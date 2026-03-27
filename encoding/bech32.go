package encoding

import "fmt"

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []int {
	ret := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, int(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, int(c&31))
	}
	return ret
}

func bech32CreateChecksum(hrp string, data []int) []int {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	ret := make([]int, 6)
	for i := 0; i < 6; i++ {
		ret[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return ret
}

// Bech32Encode encodes a bech32 string from an HRP and pre-converted 5-bit data values.
// Use ConvertBits to produce the data slice from raw bytes.
func Bech32Encode(hrp string, data []int) string {
	combined := append(data, bech32CreateChecksum(hrp, data)...)
	ret := make([]byte, 0, len(hrp)+1+len(combined))
	ret = append(ret, []byte(hrp)...)
	ret = append(ret, '1')
	for _, d := range combined {
		ret = append(ret, bech32Charset[d])
	}
	return string(ret)
}

// ConvertBits converts a byte slice from fromBits-per-group to toBits-per-group.
// If pad is true, any remaining bits are zero-padded; otherwise non-zero padding returns an error.
func ConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]int, error) {
	acc := 0
	bits := uint(0)
	maxv := (1 << toBits) - 1
	var ret []int
	for _, value := range data {
		acc = acc<<fromBits | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits {
		return nil, fmt.Errorf("illegal zero padding")
	} else if (acc<<(toBits-bits))&maxv != 0 {
		return nil, fmt.Errorf("non-zero padding")
	}
	return ret, nil
}

// Bech32EncodeBytes is a convenience wrapper: it converts raw bytes (8-bit groups)
// to 5-bit groups with padding, then bech32-encodes them. Used by Cosmos-family chains.
func Bech32EncodeBytes(hrp string, data []byte) (string, error) {
	converted, err := ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("encoding bech32 failed: %w", err)
	}
	return Bech32Encode(hrp, converted), nil
}
