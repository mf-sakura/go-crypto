package main

import "fmt"

func main() {
	input := []byte("this is test")
	outputHash := SumSha512(input)

	fmt.Printf("Sha512 of \"%s\" is \"%x\"\n", input, outputHash)

}
