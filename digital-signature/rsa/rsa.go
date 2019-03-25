package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

var (
	defaultPssOption = &rsa.PSSOptions{
		SaltLength: 100,
	}
)

// Sign Create Signature with RSAPSS
func Sign(message []byte, privateKey *rsa.PrivateKey, option *rsa.PSSOptions) ([]byte, error) {
	if option == nil {
		option = defaultPssOption
	}
	hashed := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], option)
}

// Verify Verify Signature with RSAPSS
func Verify(message, sig []byte, publicKey *rsa.PublicKey, option *rsa.PSSOptions) (bool, error) {
	if option == nil {
		option = defaultPssOption
	}
	hashed := sha256.Sum256(message)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], sig, option); err != nil {
		return false, err
	}
	return true, nil
}
