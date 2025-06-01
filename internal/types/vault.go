package types

type LibType int

const (
	GG20 LibType = iota
	DKLS
)

type VaultCreateRequest struct {
	Name               string  `json:"name" validate:"required"`
	SessionID          string  `json:"session_id" validate:"required"`
	HexEncryptionKey   string  `json:"hex_encryption_key" validate:"required"` // this is the key used to encrypt and decrypt the keygen communications
	HexChainCode       string  `json:"hex_chain_code" validate:"required"`
	LocalPartyId       string  `json:"local_party_id"`                          // when this field is empty , then server will generate a random local party id
	EncryptionPassword string  `json:"encryption_password" validate:"required"` // password used to encrypt the vault file
	Email              string  `json:"email" validate:"required"`               // this is the email of the user that the vault backup will be sent to
	LibType            LibType `json:"lib_type"`                                // this is the type of the vault
}

type ReshareRequest struct {
	Name               string   `json:"name"`                 // name of the vault
	PublicKey          string   `json:"public_key"`           // public key ecdsa
	SessionID          string   `json:"session_id"`           // session id
	HexEncryptionKey   string   `json:"hex_encryption_key"`   // hex encryption key
	HexChainCode       string   `json:"hex_chain_code"`       // hex chain code
	LocalPartyId       string   `json:"local_party_id"`       // local party id
	OldParties         []string `json:"old_parties"`          // old parties
	EncryptionPassword string   `json:"encryption_password"`  // password used to encrypt the vault file
	Email              string   `json:"email"`
	OldResharePrefix   string   `json:"old_reshare_prefix"`
	LibType            LibType  `json:"lib_type"`
}
