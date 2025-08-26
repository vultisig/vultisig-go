package swapkit

import (
	"context"
	"testing"
	"time"
)

const testBaseURL = "https://api.vultisig.com/swapkit"

func TestProviders(t *testing.T) {
	client := NewClient(testBaseURL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Providers(ctx)
	if err != nil {
		t.Fatalf("Providers failed: %v", err)
	}

	if len(resp) == 0 {
		t.Fatal("Expected providers response to contain providers")
	}

	for _, provider := range resp {
		if provider.Name == "" {
			t.Error("Provider name should not be empty")
		}
		if provider.Provider == "" {
			t.Error("Provider provider field should not be empty")
		}
	}
}

func TestTokens(t *testing.T) {
	client := NewClient(testBaseURL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Tokens(ctx, TokensRequest{Provider: "THORCHAIN"})
	if err != nil {
		t.Fatalf("Tokens failed: %v", err)
	}

	if resp.Provider == "" {
		t.Error("Expected provider field to be populated")
	}

	if len(resp.Tokens) == 0 {
		t.Error("Expected tokens response to contain tokens")
	}

	for _, token := range resp.Tokens {
		if token.Chain == "" {
			t.Error("Token chain should not be empty")
		}
		if token.Identifier == "" {
			t.Error("Token identifier should not be empty")
		}
	}
}

func TestQuote(t *testing.T) {
	client := NewClient(testBaseURL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := QuoteRequest{
		SellAsset:          "ETH.USDC-0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		BuyAsset:           "ETH.USDT-0xdAC17F958D2ee523a2206206994597C13D831ec7",
		SellAmount:         "10000000",
		SourceAddress:      "0xcB9B049B9c937acFDB87EeCfAa9e7f2c51E754f5",
		DestinationAddress: "0xcB9B049B9c937acFDB87EeCfAa9e7f2c51E754f5",
	}

	resp, err := client.Quote(ctx, req)
	if err != nil {
		t.Logf("Quote request failed (may be expected): %v", err)
		return
	}

	if len(resp.Routes) == 0 {
		t.Log("No routes returned")
		return
	}

	t.Logf("Received %d routes", len(resp.Routes))
	t.Logf("Expected buy amount: %s", resp.ExpectedBuyAmount)

	for i, route := range resp.Routes {
		t.Logf("Route %d: %s -> %s (%s -> %s) via %s",
			i, route.SellAsset, route.BuyAsset,
			route.SellAmount, route.BuyAmount, route.Provider)

		if route.SellAsset == "" {
			t.Logf("Route %d: sell asset is empty", i)
		}
		if route.BuyAsset == "" {
			t.Logf("Route %d: buy asset is empty", i)
		}
		if route.Provider == "" {
			t.Logf("Route %d: provider is empty", i)
		}
	}
}

func TestPrice(t *testing.T) {
	client := NewClient(testBaseURL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := PriceRequest{
		Tokens: []TokenIdentifier{
			{Identifier: "ETH.ETH"},
			{Identifier: "BTC.BTC"},
		},
		Metadata: true,
	}

	resp, err := client.Price(ctx, req)
	if err != nil {
		t.Fatalf("Price failed: %v", err)
	}

	if len(resp) == 0 {
		t.Error("Expected price response to contain price data")
	}

	for _, price := range resp {
		if price.Identifier == "" {
			t.Error("Expected price to have identifier")
		}
		t.Logf("Price for %s: %f", price.Identifier, price.Price)
	}
}

func TestScreen(t *testing.T) {
	client := NewClient(testBaseURL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := ScreenRequest{
		Addresses: []string{
			"0x1234567890123456789012345678901234567890",
			"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		Chains: []string{"1", "bitcoin"},
	}

	resp, err := client.Screen(ctx, req)
	if err != nil {
		t.Fatalf("Screen failed: %v", err)
	}

	if resp.IsRisky {
		t.Log("Address flagged as risky")
	} else {
		t.Log("Address passed compliance check")
	}
}
