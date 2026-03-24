package address

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetCardanoAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Cardano",
			chain: common.Cardano,
			want:  "addr1v8r9wtl43a6e2hn89xsgmgv3ccjmtud9psf7mkn3gy9l7gc7svmds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetCardanoAddress(testEdDSAPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			t.Logf("Got: %s", got)
			assert.Equal(t, tt.want, got)
		})
	}
}
