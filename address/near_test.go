package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNearAddress(t *testing.T) {
	got, err := GetNearAddress(testEdDSAPublicKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, "8265ca17b04e49dd99535d869d3510f30b7f60d60fb884427d59b47d32e6be5e", got)
}

func TestGetNearAddress_RejectsECDSAPubkey(t *testing.T) {
	_, err := GetNearAddress(testECDSAPublicKey)
	assert.ErrorContains(t, err, "Ed25519")
}
