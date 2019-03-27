package main

import "golang.org/x/crypto/bcrypt"

// GeneratePasswordHash Generate PasswordHash
func GeneratePasswordHash(password []byte, cost int) ([]byte, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return bcrypt.GenerateFromPassword(password, cost)
}

// CheckPasswordHash Check PasswordHash
func CheckPasswordHash(password, hashed []byte) error {
	return bcrypt.CompareHashAndPassword(hashed, password)
}
