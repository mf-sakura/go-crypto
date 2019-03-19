package main

import (
	"crypto/rand"
	"crypto/rsa"
)

const (
	keySize = 2048
)

// GeneratePrivateKey Generate RSA PrivateKey
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

// GeneratePublickey Generate RSA PublicKey from PrivateKey
func GeneratePublickey(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	return &privateKey.PublicKey
}
