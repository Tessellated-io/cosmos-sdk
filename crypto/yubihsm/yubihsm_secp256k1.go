package yubihsm

import (
	"fmt"
	"context"
	"crypto/ecdsa"
"crypto/elliptic"
"reflect"
"encoding/hex"


	"github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/ecadlabs/signatory/pkg/vault/yubi"
	"github.com/btcsuite/btcd/btcec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"crypto/sha256"
	// "github.com/btcsuite/btcd/btcec"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"

	// "github.com/cosmos/cosmos-sdk/codec"
)



// NewPrivKeySecp256k1Unsafe will attach to a key and store the public key for later use.
//
// This function is marked as unsafe as it will retrieve a pubkey without user verification.
// It can only be used to verify a pubkey but never to create new accounts/keys. In that case,
// please refer to NewPrivKeySecp256k1
func NewPrivKeySecp256k1Unsafe() (types.LedgerPrivKey, error) {
	config := &yubi.Config{
		Address: "127.0.0.1:12345",
		Password: "penalty humble cricket evidence resist siren offer mix submit pool swarm donkey amount cabin property joke crisp joy income little erase decrease absent onion",
		AuthKeyID: 1,
		KeyImportDomains: 1,
	}

	hsm, err := yubi.New(context.Background(), config)
	if err != nil {
		return nil, err
	}

	pubkey, err := getPubKeyUnsafe(hsm)
	if err != nil {
		return nil, err
	}

	return PrivKeyYubiHsmSecp256k1{
		CachedPubKey: pubkey,
	}, nil
}

// getPubKeyUnsafe reads the pubkey from a ledger device
//
// This function is marked as unsafe as it will retrieve a pubkey without user verification
// It can only be used to verify a pubkey but never to create new accounts/keys. In that case,
// please refer to getPubKeyAddrSafe
//
// since this involves IO, it may return an error, which is not exposed
// in the PubKey interface, so this function allows better error handling
func getPubKeyUnsafe(hsm *yubi.HSM) (types.PubKey, error) {
	fmt.Println("meybe")
	publicKey, err := hsm.GetPublicKey(context.Background(), "0af8") // Tezos, for now
	if err != nil {
		return nil, fmt.Errorf("Could not connect to yubi", err)
	}
	fmt.Println("win")

	// publicKey = storedKey.PublicKey()
	fmt.Printf("%+v\n", publicKey.PublicKey())
	fmt.Println(reflect.TypeOf(publicKey.PublicKey()))
	fmt.Println(reflect.ValueOf(publicKey.PublicKey()).Kind())
	pubKey, ok := publicKey.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Could not assert the public key to secp public key")
	}
	fmt.Println("ok!")

	pubKeyBytes := elliptic.Marshal(pubKey, pubKey.X, pubKey.Y)
	fmt.Println("alright!")

	// re-serialize in the 33-byte compressed format
	cmp, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	compressedPublicKey := make([]byte, secp256k1.PubKeySize)
	copy(compressedPublicKey, cmp.SerializeCompressed())
	fmt.Println(compressedPublicKey)


	return &secp256k1.PubKey{Key: compressedPublicKey}, nil
}

type PrivKeyYubiHsmSecp256k1 struct {
	// CachedPubKey should be private, but we want to encode it via
	// go-amino so we can view the address later, even without having the
	// ledger attached.
	CachedPubKey types.PubKey

	hsm *yubi.HSM
}

// PubKey returns the cached public key.
func (pkl PrivKeyYubiHsmSecp256k1) PubKey() types.PubKey {
	return pkl.CachedPubKey
}

func (pkl PrivKeyYubiHsmSecp256k1) Bytes() []byte {
	return cdc.MustMarshal(pkl)
}

func (pkl PrivKeyYubiHsmSecp256k1) Equals(other types.LedgerPrivKey) bool {
	if otherKey, ok := other.(PrivKeyYubiHsmSecp256k1); ok {
		return pkl.CachedPubKey.Equals(otherKey.CachedPubKey)
	}
	return false
}

func (pkl PrivKeyYubiHsmSecp256k1) Sign(msg []byte) ([]byte, error) {
	config := &yubi.Config{
		Address: "127.0.0.1:12345",
		Password: "penalty humble cricket evidence resist siren offer mix submit pool swarm donkey amount cabin property joke crisp joy income little erase decrease absent onion",
		AuthKeyID: 1,
		KeyImportDomains: 1,
	}

	hsm, err := yubi.New(context.Background(), config)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)
	fmt.Println(`Digest`)
	fmt.Println(digest)

	// digest := Digest(msg)
	// fmt.Println("digested")

	publicKey, err := hsm.GetPublicKey(context.Background(), "0af8") // Tezos, for now
	if err != nil {
		return nil, fmt.Errorf("Could not connect to yubi", err)
	}
	fmt.Println("win")


	signature, err := hsm.Sign(context.Background(), digest[:], publicKey)
	if err != nil {
		return nil, err
	}
	fmt.Println("signature")
	fmt.Println(reflect.TypeOf(signature))
	fmt.Println(reflect.ValueOf(signature).Kind())
	fmt.Println(signature.String())


	casted, ok := signature.(*cryptoutils.ECDSASignature)
	if !ok {
		return nil, fmt.Errorf("Could not assert the sig")
	}
	fmt.Println("ok!")

	canonCheckString := cryptoutils.CanonizeECDSASignature(casted)

	// btcec.NewSignature(canonCheckString.R, canonCheckString.S)


	canonCheck, err := hex.DecodeString( canonCheckString.R.Text(16) + canonCheckString.S.Text(16))
	if err != nil {
		return nil, err
	}
	fmt.Println("check is")
	fmt.Println(canonCheck)


	return canonCheck, nil
}
func (pkl PrivKeyYubiHsmSecp256k1)  Type() string {
	return "PrivKeyYubiHsmSecp256k1"
}