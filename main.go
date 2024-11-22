package main

import "github.com/dickeyy/crypgo/crypto"

func main() {
	original := []byte("Super secret message. no one shoul be able to read this.")
	hash := crypto.SHA256(original)
	println(string(hash))
}
