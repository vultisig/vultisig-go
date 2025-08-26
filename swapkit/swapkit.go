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
	Name              string   `json:"name,omitempty"`
	Provider          string   `json:"provider,omitempty"`
	Keywords          []string `json:"keywords,omitempty"`
	Count             int      `json:"count,omitempty"`
	LogoURI           string   `json:"logoURI,omitempty"`
	SupportedChainIds []string `json:"supportedChainIds,omitempty"`
}

type ProvidersResponse []Provider

type TokensRequest struct {
	Provider string `json:"provider,omitempty"`
}

type Token struct {
	Chain       string `json:"chain,omitempty"`
	Ticker      string `json:"ticker,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	Decimals    int    `json:"decimals,omitempty"`
	LogoURI     string `json:"logoURI,omitempty"`
	CoinGeckoID string `json:"coinGeckoId,omitempty"`
}

type TokensResponse struct {
	Provider  string  `json:"provider,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
	Count     int     `json:"count,omitempty"`
	Tokens    []Token `json:"tokens,omitempty"`
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

type QuoteFee struct {
	Type     string `json:"type,omitempty"`
	Amount   string `json:"amount,omitempty"`
	Asset    string `json:"asset,omitempty"`
	Chain    string `json:"chain,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type QuoteLeg struct {
	Provider             string     `json:"provider,omitempty"`
	SellAsset            string     `json:"sellAsset,omitempty"`
	SellAmount           string     `json:"sellAmount,omitempty"`
	BuyAsset             string     `json:"buyAsset,omitempty"`
	BuyAmount            string     `json:"buyAmount,omitempty"`
	BuyAmountMaxSlippage string     `json:"buyAmountMaxSlippage,omitempty"`
	Fees                 []QuoteFee `json:"fees,omitempty"`
}

type QuoteEstimatedTime struct {
	Inbound  float64 `json:"inbound,omitempty"`
	Swap     float64 `json:"swap,omitempty"`
	Outbound float64 `json:"outbound,omitempty"`
	Total    float64 `json:"total,omitempty"`
}

type QuoteWarning struct {
	Code    string `json:"code,omitempty"`
	Display string `json:"display,omitempty"`
	Tooltip string `json:"tooltip,omitempty"`
}

type QuoteRoute struct {
	SellAsset                    string             `json:"sellAsset,omitempty"`
	SellAmount                   string             `json:"sellAmount,omitempty"`
	BuyAsset                     string             `json:"buyAsset,omitempty"`
	ExpectedBuyAmount            string             `json:"expectedBuyAmount,omitempty"`
	ExpectedBuyAmountMaxSlippage string             `json:"expectedBuyAmountMaxSlippage,omitempty"`
	Fees                         []QuoteFee         `json:"fees,omitempty"`
	Providers                    []string           `json:"providers,omitempty"`
	SourceAddress                string             `json:"sourceAddress,omitempty"`
	DestinationAddress           string             `json:"destinationAddress,omitempty"`
	ApprovalAddress              string             `json:"approvalAddress,omitempty"`
	Expiration                   string             `json:"expiration,omitempty"`
	EstimatedTime                QuoteEstimatedTime `json:"estimatedTime,omitempty"`
	TotalSlippageBps             int                `json:"totalSlippageBps,omitempty"`
	Legs                         []QuoteLeg         `json:"legs,omitempty"`
	Warnings                     []QuoteWarning     `json:"warnings,omitempty"`

	// if includeTx=true
	Tx             string         `json:"tx,omitempty"`
	TargetAddress  string         `json:"targetAddress,omitempty"`
	InboundAddress string         `json:"inboundAddress,omitempty"`
	Memo           string         `json:"memo,omitempty"`
	Meta           map[string]any `json:"meta,omitempty"`
}

type QuoteProviderError struct {
	ErrorCode string `json:"errorCode,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Message   string `json:"message,omitempty"`
}

type QuoteResponse struct {
	QuoteId        string               `json:"quoteId,omitempty"`
	Routes         []QuoteRoute         `json:"routes,omitempty"`
	ProviderErrors []QuoteProviderError `json:"providerErrors,omitempty"`
}

type TrackRequest struct {
	Hash    string `json:"hash,omitempty"`
	ChainId string `json:"chainId,omitempty"`
	Block   int    `json:"block,omitempty"`
}

type TrackLeg struct {
	Status string `json:"status,omitempty"`
	Hash   string `json:"hash,omitempty"`
}

type TrackResponse struct {
	Status    string     `json:"status,omitempty"`
	Hash      string     `json:"hash,omitempty"`
	ChainId   string     `json:"chainId,omitempty"`
	FromAsset string     `json:"fromAsset,omitempty"`
	ToAsset   string     `json:"toAsset,omitempty"`
	Amount    string     `json:"amount,omitempty"`
	Legs      []TrackLeg `json:"legs,omitempty"`
}

type PriceRequest struct {
	Tokens   []TokenIdentifier `json:"tokens,omitempty"`
	Metadata bool              `json:"metadata,omitempty"`
}

type TokenIdentifier struct {
	Identifier string `json:"identifier,omitempty"`
}

type PriceCoinGeckoData struct {
	ID                          string    `json:"id,omitempty"`
	Name                        string    `json:"name,omitempty"`
	MarketCap                   float64   `json:"market_cap,omitempty"`
	TotalVolume                 float64   `json:"total_volume,omitempty"`
	PriceChange24hUSD           float64   `json:"price_change_24h_usd,omitempty"`
	PriceChangePercentage24hUSD float64   `json:"price_change_percentage_24h_usd,omitempty"`
	SparklineIn7d               []float64 `json:"sparkline_in_7d,omitempty"`
	Timestamp                   string    `json:"timestamp,omitempty"`
}

type PriceResponse []struct {
	Identifier string             `json:"identifier,omitempty"`
	Provider   string             `json:"provider,omitempty"`
	CG         PriceCoinGeckoData `json:"cg,omitempty"`
	PriceUSD   float64            `json:"price_usd,omitempty"`
	Timestamp  int64              `json:"timestamp,omitempty"`
}

type ScreenRequest struct {
	Addresses []string `json:"addresses,omitempty"`
	Chains    []string `json:"chains,omitempty"`
}

type ScreenResponse struct {
	IsRisky bool `json:"isRisky,omitempty"`
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
		return QuoteResponse{}, fmt.Errorf("failed to get quote: %w", err)
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
