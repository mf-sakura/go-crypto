package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Encrypt Encrypt
func Encrypt(publicKey *rsa.PublicKey, plainText, label []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plainText, label)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// Decrypt Decrypt. Label should match one used in encryption
func Decrypt(privateKey *rsa.PrivateKey, cipherText, label []byte) ([]byte, error) {
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, label)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
