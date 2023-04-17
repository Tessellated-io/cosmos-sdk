package yubi

import (
	"github.com/cosmos/cosmos-sdk/crypto/types"
)



// NewPrivKeySecp256k1Unsafe will attach to a key and store the public key for later use.
//
// This function is marked as unsafe as it will retrieve a pubkey without user verification.
// It can only be used to verify a pubkey but never to create new accounts/keys. In that case,
// please refer to NewPrivKeySecp256k1
func NewPrivKeySecp256k1Unsafe() (types.YubiPrivKey, error) {
	return nil, nil
}

type PrivKeyYubiSecp256k1 struct {
	// CachedPubKey should be private, but we want to encode it via
	// go-amino so we can view the address later, even without having the
	// ledger attached.
	CachedPubKey types.PubKey
}

// PubKey returns the cached public key.
func (pkl PrivKeyYubiSecp256k1) PubKey() types.PubKey {
	return pkl.CachedPubKey
}
