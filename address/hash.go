package address

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

// hash160 computes RIPEMD160(SHA256(data))
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}
