package main

import "golang.org/x/crypto/sha3"

// SumSha3_512 CheckSum of Sha3-512
func SumSha3_512(message []byte) [64]byte {
	return sha3.Sum512(message)
}
