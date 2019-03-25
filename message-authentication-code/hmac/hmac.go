package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

// CreateHMAC Create HMAC
func CreateHMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// VerifyHMAC Verify whether inputted HMAC is created by the key and message, without leaking timing information.
func VerifyHMAC(message, key, actualHMAC []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedHMAC := mac.Sum(nil)
	return hmac.Equal(actualHMAC, expectedHMAC)
}
