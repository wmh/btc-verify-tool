package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	bitcoin "github.com/bitcoinschema/go-bitcoin/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/wmh/btc-verify-tool/util"
)

func main() {
	msg := "verify: HelloHunW8"
	hexStrWithoutPrefix := "1bd7b51e76aa6bb85e4940063e66f5c348f8bdf7e86cb17dfc4002c94b17cfa31a6a6d77bfca235e66b005f5c638f298610b4a2b13ff7d26df03c9f1327a5d485c"
	showVerifyData(msg, hexStrWithoutPrefix)
}

func showVerifyData(msg, hexStr string) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}

	signedB64 := base64.StdEncoding.EncodeToString(bytes)
	publicKey, wasCompressed, err := bitcoin.PubKeyFromSignature(signedB64, msg)
	if err != nil {
		panic(err)
	}
	bscriptAddress, err := bitcoin.GetAddressFromPubKey(publicKey, wasCompressed)
	if err != nil {
		panic(err)
	}

	fmt.Println("Address:", bscriptAddress.AddressString)
	fmt.Println("Message:", msg)
	fmt.Println("Signature:", signedB64)
	fmt.Println("verify url: https://tools.qz.sg/")

	// convert public key to other types of address
	pubkey := (ecdsa.PublicKey)(*publicKey)
	fmt.Println("----------------------------")
	fmt.Println("derive addresses (Mainnet):")
	addrsFromPubkey(util.MainNet, &pubkey)

	fmt.Println("----------------------------")
	fmt.Println("derive addresses (Testnet):")
	addrsFromPubkey(util.TestNet, &pubkey)
}

func addrsFromPubkey(net *chaincfg.Params, pubkey *ecdsa.PublicKey) {
	secpPubkey := util.PubKeyFromCryptoECDSA(pubkey)
	fmt.Println("Legacy:", util.PubKeyToPubKeyHash(net, secpPubkey))
	fmt.Println("Nested SegWit:", util.PubKeyToScriptHash(net, secpPubkey))
	fmt.Println("SegWit:", util.PubKeyToWitnessPubKeyHash(net, secpPubkey))
}
