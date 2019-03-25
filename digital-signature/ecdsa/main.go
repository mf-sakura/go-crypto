package main

import "fmt"

var (
	message = []byte("this is test")
)

func main() {

	privateKey, err := GenerateKey()
	if err != nil {
		fmt.Printf("Failed to GenerateKey. error:%v", err)
		return
	}
	publicKey := &privateKey.PublicKey

	r, s, err := Sign(message, privateKey)

	if err != nil {
		fmt.Printf("Failed to Sign. error:%v", err)
		return
	}
	fmt.Printf("Sign result r is %d, s is %d", r, s)
	result := Verify(message, publicKey, r, s)
	fmt.Printf("Result of Verify is %t\n", result)
}
