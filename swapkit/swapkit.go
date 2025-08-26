package swapkit

import (
	"context"
	"fmt"

	"github.com/vultisig/vultisig-go/internal/libhttp"
)

type Client struct {
	baseURL string
	apiKey  string
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

type ProvidersRequest struct{}

type Provider struct {
	Name              string   `json:"name"`
	Provider          string   `json:"provider"`
	Keywords          []string `json:"keywords"`
	Count             int      `json:"count"`
	LogoURI           string   `json:"logoURI"`
	SupportedChainIds []string `json:"supportedChainIds"`
}

type ProvidersResponse []Provider

type TokensRequest struct {
	Provider string `json:"provider"`
}

type Token struct {
	Chain       string `json:"chain"`
	Ticker      string `json:"ticker"`
	Identifier  string `json:"identifier"`
	Decimals    int    `json:"decimals"`
	LogoURI     string `json:"logoURI"`
	CoinGeckoID string `json:"coinGeckoId,omitempty"`
}

type TokensResponse struct {
	Provider  string  `json:"provider"`
	Timestamp string  `json:"timestamp"`
	Count     int     `json:"count"`
	Tokens    []Token `json:"tokens"`
}

type QuoteRequest struct {
	SellAsset                  string   `json:"sellAsset"`
	BuyAsset                   string   `json:"buyAsset"`
	SellAmount                 string   `json:"sellAmount"`
	SourceAddress              string   `json:"sourceAddress"`
	DestinationAddress         string   `json:"destinationAddress"`
	Providers                  []string `json:"providers,omitempty"`
	Slippage                   float64  `json:"slippage,omitempty"`
	Affiliate                  string   `json:"affiliate,omitempty"`
	AffiliateFee               int      `json:"affiliateFee,omitempty"`
	AllowSmartContractSender   bool     `json:"allowSmartContractSender,omitempty"`
	AllowSmartContractReceiver bool     `json:"allowSmartContractReceiver,omitempty"`
	DisableSecurityChecks      bool     `json:"disableSecurityChecks,omitempty"`
	IncludeTx                  bool     `json:"includeTx,omitempty"`
	CfBoost                    bool     `json:"cfBoost,omitempty"`
}

type Quote struct {
	Provider           string `json:"provider"`
	SellAsset          string `json:"sellAsset"`
	SellAmount         string `json:"sellAmount"`
	BuyAsset           string `json:"buyAsset"`
	BuyAmount          string `json:"buyAmount"`
	SourceAddress      string `json:"sourceAddress"`
	DestinationAddress string `json:"destinationAddress"`
	Fees               string `json:"fees"`
	Time               int    `json:"time"`
	CallData           string `json:"calldata"`
	Contract           string `json:"contract"`
}

type QuoteResponse []Quote

type TrackRequest struct {
	Hash    string `json:"hash"`
	ChainId string `json:"chainId"`
	Block   int    `json:"block"`
}

type TrackLeg struct {
	Status string `json:"status"`
	Hash   string `json:"hash"`
}

type TrackResponse struct {
	Status    string     `json:"status"`
	Hash      string     `json:"hash"`
	ChainId   string     `json:"chainId"`
	FromAsset string     `json:"fromAsset"`
	ToAsset   string     `json:"toAsset"`
	Amount    string     `json:"amount"`
	Legs      []TrackLeg `json:"legs"`
}

type PriceRequest struct {
	Tokens   []TokenIdentifier `json:"tokens"`
	Metadata bool              `json:"metadata"`
}

type TokenIdentifier struct {
	Identifier string `json:"identifier"`
}

type PriceMetadata struct {
	MarketCap       float64 `json:"market_cap,omitempty"`
	Volume24h       float64 `json:"total_volume,omitempty"`
	PriceChange24h  float64 `json:"price_change_24h,omitempty"`
	PriceChangePerc float64 `json:"price_change_percentage_24h,omitempty"`
}

type PriceResponse []struct {
	Identifier string        `json:"identifier"`
	Price      float64       `json:"price"`
	Timestamp  int64         `json:"timestamp"`
	Metadata   PriceMetadata `json:"metadata,omitempty"`
}

type ScreenRequest struct {
	Addresses interface{} `json:"addresses"`
	Chains    []string    `json:"chains"`
}

type ScreenResponse struct {
	IsRisky bool `json:"isRisky"`
}

func (c *Client) getHeaders() map[string]string {
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	if c.apiKey != "" {
		headers["Authorization"] = "Bearer " + c.apiKey
	}
	return headers
}

func (c *Client) Providers(ctx context.Context) (ProvidersResponse, error) {
	result, err := libhttp.Call[ProvidersResponse](
		ctx,
		"GET",
		c.baseURL+"/providers",
		c.getHeaders(),
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}
	return result, nil
}

func (c *Client) Tokens(ctx context.Context, req TokensRequest) (TokensResponse, error) {
	var query map[string]string
	if req.Provider != "" {
		query = map[string]string{"provider": req.Provider}
	}

	result, err := libhttp.Call[TokensResponse](
		ctx,
		"GET",
		c.baseURL+"/tokens",
		c.getHeaders(),
		nil,
		query,
	)
	if err != nil {
		return TokensResponse{}, fmt.Errorf("failed to get tokens: %w", err)
	}
	return result, nil
}

func (c *Client) Quote(ctx context.Context, req QuoteRequest) (QuoteResponse, error) {
	result, err := libhttp.Call[QuoteResponse](
		ctx,
		"POST",
		c.baseURL+"/quote",
		c.getHeaders(),
		req,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}
	return result, nil
}

func (c *Client) Track(ctx context.Context, req TrackRequest) (TrackResponse, error) {
	result, err := libhttp.Call[TrackResponse](
		ctx,
		"POST",
		c.baseURL+"/track",
		c.getHeaders(),
		req,
		nil,
	)
	if err != nil {
		return TrackResponse{}, fmt.Errorf("failed to track transaction: %w", err)
	}
	return result, nil
}

func (c *Client) Price(ctx context.Context, req PriceRequest) (PriceResponse, error) {
	result, err := libhttp.Call[PriceResponse](
		ctx,
		"POST",
		c.baseURL+"/price",
		c.getHeaders(),
		req,
		nil,
	)
	if err != nil {
		return PriceResponse{}, fmt.Errorf("failed to get price: %w", err)
	}
	return result, nil
}

func (c *Client) Screen(ctx context.Context, req ScreenRequest) (ScreenResponse, error) {
	result, err := libhttp.Call[ScreenResponse](
		ctx,
		"POST",
		c.baseURL+"/screen",
		c.getHeaders(),
		req,
		nil,
	)
	if err != nil {
		return ScreenResponse{}, fmt.Errorf("failed to screen addresses: %w", err)
	}
	return result, nil
}
