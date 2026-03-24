package address

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetTonAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Ton",
			chain: common.Ton,
			want:  "UQCffA0At2bHaJ9jbtjkfekp4gq3JxU411fRGeJe80nGm8rx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTonAddress(testEdDSAPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
