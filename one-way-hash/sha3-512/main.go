package main

import "fmt"

func main() {
	input := []byte("this is test")
	outputHash := SumSha3_512(input)

	fmt.Printf("Sha3-512 of \"%s\" is \"%x\"\n", input, outputHash)

}
