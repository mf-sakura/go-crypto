package main

import "crypto/sha512"

// SumSha512 CheckSum of Sha512
func SumSha512(message []byte) [64]byte {
	return sha512.Sum512(message)
}
