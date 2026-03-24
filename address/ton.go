package address

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/xssnick/tonutils-go/ton/wallet"
)

func GetTonAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key length: expected %d bytes, got %d bytes", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	addr, err := wallet.AddressFromPubKey(pubKey, wallet.V4R2, wallet.DefaultSubwallet)
	if err != nil {
		return "", fmt.Errorf("failed to derive TON address: %w", err)
	}
	addr.SetBounce(false)

	return addr.String(), nil
}
