package main

import (
	"crypto/aes"
	"fmt"
)

func main() {
	plainText := []byte("Bob loves Alice.")
	key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")
	iv := key[:aes.BlockSize]
	// Create new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("NewCipher err: %v\n", err)
		return
	}

	cipherText := EncryptCBC(block, iv, plainText)
	fmt.Printf("CBC Encrypted text is %x\n", cipherText)
	decryptedText := DecryptCBC(block, iv, cipherText)
	fmt.Printf("CBC Decrypted text is %s\n", decryptedText)

	cipherText2 := EncryptCTR(block, iv, plainText)
	fmt.Printf("CTR Encrypted text is %x\n", cipherText2)
	decryptedText2 := DecryptCTR(block, iv, cipherText2)
	fmt.Printf("CTR Decrypted text is %s\n", decryptedText2)
}
