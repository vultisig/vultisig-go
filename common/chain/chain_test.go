package chain

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChainMetadata(t *testing.T) {
	tests := []struct {
		chain      Chain
		name       string
		symbol     string
		derivePath string
		isEdDSA    bool
		isMLDSA    bool
		evmID      int64
	}{
		{chain: Robinhood, name: "Robinhood", symbol: "ETH", derivePath: "m/44'/60'/0'/0/0", evmID: 4663},
		{chain: Near, name: "Near", symbol: "NEAR", isEdDSA: true},
		{chain: QBTC, name: "QBTC", symbol: "QBTC", isMLDSA: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, tt.chain.String())

			got, err := FromString(tt.name)
			require.NoError(t, err)
			assert.Equal(t, tt.chain, got)

			var decoded Chain
			raw, err := json.Marshal(tt.chain)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &decoded))
			assert.Equal(t, tt.chain, decoded)

			symbol, err := tt.chain.NativeSymbol()
			require.NoError(t, err)
			assert.Equal(t, tt.symbol, symbol)

			assert.Equal(t, tt.derivePath, tt.chain.GetDerivePath())
			assert.Equal(t, tt.isEdDSA, tt.chain.IsEdDSA())
			assert.Equal(t, tt.isMLDSA, tt.chain.IsMLDSA())

			evmID, err := tt.chain.EvmID()
			if tt.evmID == 0 {
				assert.Error(t, err)
				assert.False(t, tt.chain.IsEvm())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.evmID, evmID.Int64())
			assert.True(t, tt.chain.IsEvm())
		})
	}
}
