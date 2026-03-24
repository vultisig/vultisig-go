package address

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetDotAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Dot",
			chain: common.Polkadot,
			want:  "13wyTqpCftZqCj9uRHxpjYrMpJzotBsr1nXdNXVXRfj1s9Gs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDotAddress(testEdDSAPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			t.Logf("Got: %s", got)
			assert.Equal(t, tt.want, got)
		})
	}
}
