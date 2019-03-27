package main

import "fmt"

func main() {
	password := []byte("aaa")
	outputHash, err := GeneratePasswordHash(password, 0)
	if err != nil {
		fmt.Printf("GeneratePasswordHash error : %v", err)
	}
	fmt.Printf("Bcrypt of \"%s\" is \"%x\"\n", password, outputHash)

	if err := CheckPasswordHash(password, outputHash); err != nil {
		fmt.Println("CheckPasswordHash failed.")
	}

}
