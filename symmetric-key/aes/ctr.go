package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func EncryptCTR(block cipher.Block, iv, plainText []byte) []byte {
	if len(plainText)%aes.BlockSize != 0 {
		plainText = PadSlice(plainText)
	}
	cipherText := make([]byte, len(plainText))
	// if len(plainText)%aes.BlockSize != 0 then CryptBlocks panic. IV also do.
	cipher.NewCTR(block, iv).XORKeyStream(cipherText, plainText)
	return cipherText
}

func DecryptCTR(block cipher.Block, iv, cipherText []byte) []byte {
	if len(cipherText)%aes.BlockSize != 0 {
		cipherText = PadSlice(cipherText)
	}
	plainText := make([]byte, len(cipherText))
	cipher.NewCTR(block, iv).XORKeyStream(plainText, cipherText)
	// trim padding
	trimmed := bytes.Trim(plainText, "\x00")
	return trimmed
}
