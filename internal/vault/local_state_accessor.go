package vault

import (
	"fmt"
	"sync"
)

// LocalStateAccessor manages local keyshare state
type LocalStateAccessor struct {
	localStates sync.Map
}

// NewLocalStateAccessor creates a new local state accessor
func NewLocalStateAccessor() *LocalStateAccessor {
	return &LocalStateAccessor{}
}

// SaveLocalState saves a keyshare to local state
func (lsa *LocalStateAccessor) SaveLocalState(publicKey string, keyshare string) error {
	if publicKey == "" {
		return fmt.Errorf("public key cannot be empty")
	}
	if keyshare == "" {
		return fmt.Errorf("keyshare cannot be empty")
	}
	
	lsa.localStates.Store(publicKey, keyshare)
	return nil
}

// GetLocalState retrieves a keyshare from local state
func (lsa *LocalStateAccessor) GetLocalState(publicKey string) (string, error) {
	if publicKey == "" {
		return "", fmt.Errorf("public key cannot be empty")
	}
	
	keyshare, exists := lsa.localStates.Load(publicKey)
	if !exists {
		return "", fmt.Errorf("keyshare not found for public key: %s", publicKey)
	}
	
	keyshareStr, ok := keyshare.(string)
	if !ok {
		return "", fmt.Errorf("invalid keyshare type for public key: %s", publicKey)
	}
	
	return keyshareStr, nil
}

// HasLocalState checks if a keyshare exists for the given public key
func (lsa *LocalStateAccessor) HasLocalState(publicKey string) bool {
	_, exists := lsa.localStates.Load(publicKey)
	return exists
}

// ClearLocalState removes a keyshare from local state
func (lsa *LocalStateAccessor) ClearLocalState(publicKey string) {
	lsa.localStates.Delete(publicKey)
}

// ClearAllLocalStates removes all keyshares from local state
func (lsa *LocalStateAccessor) ClearAllLocalStates() {
	lsa.localStates.Range(func(key, value interface{}) bool {
		lsa.localStates.Delete(key)
		return true
	})
}