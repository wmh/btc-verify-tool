package util

import (
	"crypto/ecdsa"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestNet represents the testnet network.
var TestNet = &chaincfg.TestNet3Params

// MainNet represents the mainnet network.
var MainNet = &chaincfg.MainNetParams

// PubKeyFromCryptoECDSA converts a crypto/ecdsa public key to a dcrd secp256k1 public key.
func PubKeyFromCryptoECDSA(pubkey *ecdsa.PublicKey) *secp.PublicKey {
	x := secp.FieldVal{}
	xb := [32]byte(pubkey.X.Bytes())
	x.SetBytes(&xb)
	y := secp.FieldVal{}
	yb := [32]byte(pubkey.Y.Bytes())
	y.SetBytes(&yb)
	return secp.NewPublicKey(&x, &y)
}

// PubKeyToPubKey converts a public key to a pub key address
func PubKeyToPubKey(net *chaincfg.Params, serializedPubKey []byte) string {
	addressPubKey, err := btcutil.NewAddressPubKey(serializedPubKey, net)
	if err != nil {
		panic(err)
	}
	return addressPubKey.EncodeAddress()
}

// WifToPubKeyHash converts a WIF to a public key hash. (BIP44)
func WifToPubKeyHash(net *chaincfg.Params, wif *btcutil.WIF) string {
	return PubKeyToPubKeyHash(net, wif.PrivKey.PubKey())
}

// PubKeyToPubKeyHash converts a public key to a public key hash.
func PubKeyToPubKeyHash(net *chaincfg.Params, pubkey *secp.PublicKey) string {
	witnessProg := btcutil.Hash160(pubkey.SerializeCompressed())
	addressPubKeyHash, err := btcutil.NewAddressPubKeyHash(witnessProg, net)
	if err != nil {
		panic(err)
	}
	return addressPubKeyHash.EncodeAddress()
}

// WifToScriptHash converts a WIF to a script hash. (BIP49)
func WifToScriptHash(net *chaincfg.Params, wif *btcutil.WIF) string {
	return PubKeyToScriptHash(net, wif.PrivKey.PubKey())
}

// PubKeyToScriptHash converts a public key to a script hash.
func PubKeyToScriptHash(net *chaincfg.Params, pubkey *secp.PublicKey) string {
	witnessProg := btcutil.Hash160(pubkey.SerializeCompressed())
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, net) // AddressWitnessPubKeyHash
	serializedScript, err := txscript.PayToAddrScript(addressWitnessPubKeyHash)
	if err != nil {
		panic(err)
	}
	addressScriptHash, err := btcutil.NewAddressScriptHash(serializedScript, net) // AddressScriptHash
	if err != nil {
		panic(err)
	}
	return addressScriptHash.EncodeAddress()
}

// WifToWitnessPubKeyHash converts a WIF to a witness public key hash. (BIP84)
func WifToWitnessPubKeyHash(net *chaincfg.Params, wif *btcutil.WIF) string {
	return PubKeyToWitnessPubKeyHash(net, wif.PrivKey.PubKey())
}

// PubKeyToWitnessPubKeyHash converts a public key to a witness public key hash.
func PubKeyToWitnessPubKeyHash(net *chaincfg.Params, pubkey *secp.PublicKey) string {
	witnessProg := btcutil.Hash160(pubkey.SerializeCompressed())
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, net)
	if err != nil {
		panic(err)
	}
	return addressWitnessPubKeyHash.EncodeAddress()
}
