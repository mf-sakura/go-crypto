package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// Sign Create Signature with ECDSA
func Sign(message []byte, privateKey *ecdsa.PrivateKey) (*big.Int, *big.Int, error) {
	hashed := sha256.Sum256(message)
	return ecdsa.Sign(rand.Reader, privateKey, hashed[:])
}

// Verify Verify Signature with ECDSA
func Verify(message []byte, publicKey *ecdsa.PublicKey, r, s *big.Int) bool {
	hashed := sha256.Sum256(message)
	return ecdsa.Verify(publicKey, hashed[:], r, s)
}
