// Package ss58 implements Substrate SS58 address encoding.
// It depends on golang.org/x/crypto/blake2b and is kept in a sub-package so
// that the parent encoding package remains dependency-free.
package ss58

import (
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
	"golang.org/x/crypto/blake2b"
)

// SS58Encode encodes a Substrate public key to SS58 format.
// format is the network prefix: 0 = Polkadot, 2 = Kusama, 42 = generic/Bittensor, etc.
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
	return encoding.Base58Encode(append(body, hash[:2]...)), nil
}

func ss58Hash(data []byte) [64]byte {
	return blake2b.Sum512(append([]byte("SS58PRE"), data...))
}
