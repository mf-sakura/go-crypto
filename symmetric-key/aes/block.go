package main

import (
	"crypto/aes"
)

func PadSlice(src []byte) []byte {
	// src must be a multiple of block size
	mult := int((len(src) / aes.BlockSize) + 1)
	leng := aes.BlockSize * mult

	srcPadded := make([]byte, leng)
	copy(srcPadded, src)
	return srcPadded
}
