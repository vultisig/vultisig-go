package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// EncryptGCM encrypts plaintext using AES-GCM with the provided hex encryption key
// This follows the same pattern as verifier/common/utils.go EncryptGCM
func EncryptGCM(plainText string, hexEncryptKey string) (string, error) {
	passwd, err := hex.DecodeString(hexEncryptKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(passwd)
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce. Nonce size is specified by GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal encrypts and authenticates plaintext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptGCM decrypts data using AES-GCM with the provided hex encryption key
// This follows the same pattern as verifier/common/utils.go DecryptGCM
func DecryptGCM(rawData []byte, hexEncryptKey string) ([]byte, error) {
	password, err := hex.DecodeString(hexEncryptKey)
	if err != nil {
		return nil, err
	}

	// Hash the password to create a key
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(rawData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the vault
	nonce, ciphertext := rawData[:nonceSize], rawData[nonceSize:]

	// Decrypt the vault
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}