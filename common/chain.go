package common

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

type Chain int

const (
	Undefined Chain = iota
	THORChain
	Solana
	Ethereum
	Avalanche
	BscChain
	Bitcoin
	BitcoinCash
	Litecoin
	Dogecoin
	GaiaChain
	Kujira
	Dash
	MayaChain
	Arbitrum
	Base
	Optimism
	Polygon
	Blast
	CronosChain
	Sui
	Polkadot
	Zksync
	Dydx
	Ton
	Terra
	TerraClassic
	XRP
	Osmosis
	Noble
	Tron
)

var chainToString = map[Chain]string{
	THORChain:    "THORChain",
	Solana:       "Solana",
	Ethereum:     "Ethereum",
	Avalanche:    "Avalanche",
	BscChain:     "BSC",
	Bitcoin:      "Bitcoin",
	BitcoinCash:  "BitcoinCash",
	Litecoin:     "Litecoin",
	Dogecoin:     "Dogecoin",
	GaiaChain:    "Cosmos",
	Kujira:       "Kujira",
	Dash:         "Dash",
	MayaChain:    "MayaChain",
	Arbitrum:     "Arbitrum",
	Base:         "Base",
	Optimism:     "Optimism",
	Polygon:      "Polygon",
	Blast:        "Blast",
	CronosChain:  "CronosChain",
	Sui:          "Sui",
	Polkadot:     "Polkadot",
	Zksync:       "Zksync",
	Dydx:         "Dydx",
	Ton:          "TON",
	Terra:        "Terra",
	TerraClassic: "TerraClassic",
	XRP:          "XRP",
	Osmosis:      "Osmosis",
	Noble:        "Noble",
	Tron:         "Tron",
}

func FromString(str string) (Chain, error) {
	for key, value := range chainToString {
		if strings.EqualFold(value, str) {
			return key, nil
		}
	}
	return Undefined, fmt.Errorf("unsupported chain: %s", str)
}

var chainDerivePath = map[Chain]string{
	Bitcoin:      "m/84'/0'/0'/0/0",
	Ethereum:     "m/44'/60'/0'/0/0",
	THORChain:    "m/44'/931'/0'/0/0",
	MayaChain:    "m/44'/931'/0'/0/0",
	Arbitrum:     "m/44'/60'/0'/0/0",
	Avalanche:    "m/44'/60'/0'/0/0",
	BscChain:     "m/44'/60'/0'/0/0",
	Base:         "m/44'/60'/0'/0/0",
	BitcoinCash:  "m/44'/145'/0'/0/0",
	Blast:        "m/44'/60'/0'/0/0",
	CronosChain:  "m/44'/60'/0'/0/0",
	Dash:         "m/44'/5'/0'/0/0",
	Dogecoin:     "m/44'/3'/0'/0/0",
	Dydx:         "m/44'/118'/0'/0/0",
	GaiaChain:    "m/44'/118'/0'/0/0",
	Kujira:       "m/44'/118'/0'/0/0",
	Terra:        "m/44'/330'/0'/0/0",
	TerraClassic: "m/44'/330'/0'/0/0",
	Litecoin:     "m/84'/2'/0'/0/0",
	Optimism:     "m/44'/60'/0'/0/0",
	Polygon:      "m/44'/60'/0'/0/0",
	Zksync:       "m/44'/60'/0'/0/0",
	Solana:       "",
	Sui:          "",
	Polkadot:     "",
	Ton:          "",
	XRP:          "m/44'/144'/0'/0/0",
	Osmosis:      "m/44'/118'/0'/0/0",
	Noble:        "m/44'/118'/0'/0/0",
	Tron:         "m/44'/195'/0'/0/0",
}

func (c Chain) IsEvm() bool {
	_, err := c.EvmID()
	return err == nil
}

func (c Chain) EvmID() (*big.Int, error) {
	switch c {
	case Ethereum:
		return big.NewInt(1), nil
	case Arbitrum:
		return big.NewInt(42161), nil
	case Avalanche:
		return big.NewInt(43114), nil
	case BscChain:
		return big.NewInt(56), nil
	case Base:
		return big.NewInt(8453), nil
	case Blast:
		return big.NewInt(81457), nil
	case CronosChain:
		return big.NewInt(25), nil
	case Optimism:
		return big.NewInt(10), nil
	case Polygon:
		return big.NewInt(137), nil
	case Zksync:
		return big.NewInt(324), nil
	default:
		return nil, fmt.Errorf("no EVM ID for this chain: %d", c)
	}
}

func (c Chain) NativeSymbol() (string, error) {
	switch c {
	case THORChain:
		return "RUNE", nil
	case Solana:
		return "SOL", nil
	case Ethereum:
		return "ETH", nil
	case Avalanche:
		return "AVAX", nil
	case BscChain:
		return "BNB", nil
	case Bitcoin:
		return "BTC", nil
	case BitcoinCash:
		return "BCH", nil
	case Litecoin:
		return "LTC", nil
	case Dogecoin:
		return "DOGE", nil
	case GaiaChain:
		return "ATOM", nil
	case Kujira:
		return "KUJI", nil
	case Dash:
		return "DASH", nil
	case MayaChain:
		return "CACAO", nil
	case Arbitrum:
		return "ETH", nil
	case Base:
		return "ETH", nil
	case Optimism:
		return "ETH", nil
	case Polygon:
		return "MATIC", nil
	case Blast:
		return "ETH", nil
	case CronosChain:
		return "CRO", nil
	case Sui:
		return "SUI", nil
	case Polkadot:
		return "DOT", nil
	case Zksync:
		return "ETH", nil
	case Dydx:
		return "DYDX", nil
	case Ton:
		return "TON", nil
	case Terra:
		return "LUNA", nil
	case TerraClassic:
		return "LUNC", nil
	case XRP:
		return "XRP", nil
	case Osmosis:
		return "OSMO", nil
	case Noble:
		return "USDC", nil
	case Tron:
		return "TRX", nil
	default:
		return "", fmt.Errorf("unsupported chain: %v", c)
	}
}

func (c Chain) String() string {
	if str, ok := chainToString[c]; ok {
		return str
	}
	return "UNKNOWN"
}
func (c Chain) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Chain) UnmarshalJSON(data []byte) error {
	var chainStr string
	if err := json.Unmarshal(data, &chainStr); err != nil {
		return err
	}
	for key, value := range chainToString {
		if value == chainStr {
			*c = key
			return nil
		}
	}
	return nil
}
func (c Chain) Value() (driver.Value, error) {
	return c.String(), nil
}

func (c *Chain) Scan(value interface{}) error {
	if value == nil {
		*c = 0
		return nil
	}

	str, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan Chain enum: %v", value)
	}
	for key, value := range chainToString {
		if value == string(str) {
			*c = key
			return nil
		}
	}
	return nil
}

func (c Chain) GetDerivePath() string {
	if str, ok := chainDerivePath[c]; ok {
		return str
	}
	return ""
}

func (c Chain) IsEdDSA() bool {
	if c == Solana || c == Sui || c == Polkadot || c == Ton {
		return true
	}
	return false
}
