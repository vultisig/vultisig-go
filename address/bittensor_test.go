package address

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetBittensorAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Bittensor",
			chain: common.Bittensor,
			want:  "5F1gKWZ8p7JMmC9PTeupbQ2Cxh1ABtKhwHo9DEWAsahVgVnU",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBittensorAddress(testEdDSAPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			t.Logf("Got: %s", got)
			assert.Equal(t, tt.want, got)
		})
	}
}
