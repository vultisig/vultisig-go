package address

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecompressSecp256k1(t *testing.T) {
	// Generator point G.
	g, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	got, err := decompressSecp256k1(g)
	assert.NoError(t, err)
	assert.Equal(t,
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"+
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		hex.EncodeToString(got))
}

func TestDecompressPointRejectsInvalid(t *testing.T) {
	tests := map[string]string{
		"too short":       "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817",
		"uncompressed":    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"x >= p":          "02" + strings.Repeat("ff", 32),
		"x not on curve":  "02" + strings.Repeat("00", 31) + "05",
		"EdDSA-sized key": testEdDSAPublicKey,
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(key)
			assert.NoError(t, err)
			_, _, err = decompressPoint(b)
			assert.Error(t, err)
		})
	}
}
