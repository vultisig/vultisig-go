package address

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetSolAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Solana",
			chain: common.Solana,
			want:  "9n22P31fnT9HscWos3jLEgvPG4HHwQehMJ8dhby18hcy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetSolAddress(testEdDSAPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
