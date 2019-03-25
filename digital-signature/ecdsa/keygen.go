package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

var (
	curve = elliptic.P256()
)

// GenerateKey Generate PrivateKey
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}
