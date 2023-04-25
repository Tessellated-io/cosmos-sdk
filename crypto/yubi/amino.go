package yubi

import (
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec"
	cryptoAmino "github.com/cosmos/cosmos-sdk/crypto/codec"
)

var cdc = codec.NewLegacyAmino()

func init() {
	// panic("THERE")

	RegisterAmino(cdc)
	cryptoAmino.RegisterCrypto(cdc)
	fmt.Println("REGISTERED")
}

// RegisterAmino registers all go-crypto related types in the given (amino) codec.
func RegisterAmino(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(PrivKeyYubiSecp256k1{},
		"tendermint/PrivKeyYubiSecp256k1", nil)
}
