package main

import "crypto/sha256"

// SumSha256 CheckSum of Sha256
func SumSha256(message []byte) [32]byte {
	return sha256.Sum256(message)
}
