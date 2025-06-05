package vault

import (
	"github.com/vultisig/vultisig-go/internal/crypto"
)

// EncryptGCM encrypts plaintext using AES-GCM with the provided hex encryption key
// This is a wrapper around the crypto package for backward compatibility
func EncryptGCM(plainText string, hexEncryptKey string) (string, error) {
	return crypto.EncryptGCM(plainText, hexEncryptKey)
}

// DecryptGCM decrypts data using AES-GCM with the provided hex encryption key
// This is a wrapper around the crypto package for backward compatibility
func DecryptGCM(rawData []byte, hexEncryptKey string) ([]byte, error) {
	return crypto.DecryptGCM(rawData, hexEncryptKey)
}
