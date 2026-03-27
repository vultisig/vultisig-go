package address

import "fmt"

// SS58Encode encodes data and format identifier to an SS58 checksumed string.
func SS58Encode(pubkey []byte, format uint16) (string, error) {
	ident := format & 0b0011_1111_1111_1111
	var prefix []byte
	if ident <= 63 {
		prefix = []byte{uint8(ident)}
	} else if ident <= 16_383 {
		first := uint8(ident & 0b0000_0000_1111_1100 >> 2)
		second := uint8(ident>>8) | uint8(ident&0b0000_0000_0000_0011)<<6
		prefix = []byte{first | 0b01000000, second}
	} else {
		return "", fmt.Errorf("unreachable: masked out the upper two bits")
	}
	body := append(prefix, pubkey...)
	hash := ss58Hash(body)
	return base58Encode(append(body, hash[:2]...)), nil
}

func ss58Hash(data []byte) [64]byte {
	prefix := []byte("SS58PRE")
	return blake2bSum512(append(prefix, data...))
}
