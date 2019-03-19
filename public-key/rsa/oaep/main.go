package main

import (
	"fmt"
	"reflect"
)

const (
	plainText = "aaaa"
	label     = "test"
)

func main() {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Failed to GeneratePrivateKey. error:%v", err)
		return
	}
	publicKey := GeneratePublickey(privateKey)
	cipherText, err := Encrypt(publicKey, []byte(plainText), []byte(label))
	if err != nil {
		fmt.Printf("Failed to Encrypt. error:%v", err)
		return
	}
	fmt.Printf("HexEncoded CipherText is %x\n", cipherText)

	decryptedText, err := Decrypt(privateKey, cipherText, []byte(label))
	if err != nil {
		fmt.Printf("Failed to Encrypt. error:%v", err)
		return
	}
	fmt.Printf("DecryptedText is %s\n", decryptedText)

	if !reflect.DeepEqual(decryptedText, []byte(plainText)) {
		fmt.Println("Decrypted text doesn't match plain text.")
	}
}
