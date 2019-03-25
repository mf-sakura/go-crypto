package main

import "fmt"

func main() {
	input := []byte("this is test")
	outputHash := SumSha256(input)

	fmt.Printf("Sha256 of \"%s\" is \"%x\"\n", input, outputHash)

}
