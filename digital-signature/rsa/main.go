package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

var (
	message = []byte("this is test")
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Printf("Failed to GeneratePrivateKey. error:%v", err)
		return
	}
	publicKey := &privateKey.PublicKey
	sig, err := Sign(message, privateKey, nil)
	if err != nil {
		fmt.Printf("Failed to Sign. error:%v", err)
		return
	}
	fmt.Printf("HexEncoded Sign is %x\n", sig)

	result, err := Verify(message, sig, publicKey, nil)
	if err != nil {
		fmt.Printf("Failed to Verify. error:%v", err)
		return
	}

	fmt.Printf("Verify result is %t\n", result)
}
