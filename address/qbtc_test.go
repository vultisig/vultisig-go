package address

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testMLDSAPublicKey is a synthetic ML-DSA-44-sized key (bytes 0..255
// repeating). Address derivation only hashes the bytes, so it need not
// be a valid lattice key.
var testMLDSAPublicKey = func() string {
	b := make([]byte, MLDSA44PublicKeySize)
	for i := range b {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}()

func TestGetQBTCAddress(t *testing.T) {
	got, err := GetQBTCAddress(testMLDSAPublicKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, "qbtc1zpa0xxx9txtyhkypzsyfe94rwwx56kl4xvcwvq", got)
}

func TestGetQBTCAddress_RejectsNonMLDSAPubkey(t *testing.T) {
	for _, key := range []string{testECDSAPublicKey, testEdDSAPublicKey} {
		_, err := GetQBTCAddress(key)
		assert.ErrorContains(t, err, "ML-DSA-44")
	}
}
