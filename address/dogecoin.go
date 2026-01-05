package address

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// DogeMainNetParams defines the network parameters for the Dogecoin main network.
var DogeMainNetParams = chaincfg.Params{
	Name: "mainnet",
	Net:  0xc0c0c0c0, // Dogecoin mainnet magic bytes

	// Address encoding magics
	PubKeyHashAddrID: 0x1E, // starts with D
	ScriptHashAddrID: 0x16, // starts with 9 or A
}

func GetDogecoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Dogecoin uses P2PKH addresses (no native SegWit support)
	pubKeyHash := btcutil.Hash160(pubKeyBytes)
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &DogeMainNetParams)
	if err != nil {
		return "", fmt.Errorf("fail to get public key hash address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

