package main

import "fmt"

func main() {
	message := []byte("this is test")
	key := []byte("key")
	hmac := CreateHMAC(message, key)

	fmt.Printf("HMAC of {key:\"%s\", message: \"%s\"} is \"%x\"\n", key, message, hmac)

}
