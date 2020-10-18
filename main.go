package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/hima398/pairing-based-crypto/pairing/paillier"
)

func main() {
	// RSA
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	msg := []byte{1}
	rsaEm, _ := rsa.EncryptPKCS1v15(rand.Reader, &rsaPriv.PublicKey, msg)

	// TODO Decrypt
	fmt.Printf("%v\n", rsaEm)

	// Paillier
	priv, _ := paillier.GenerateKey(rand.Reader, 2048)

	m := big.NewInt(1)
	c := paillier.Encrypt(m, &priv.PublicKey)

	m2 := priv.Decrypt(c)
	fmt.Printf("c = %v\n", c)
	fmt.Printf("m = %v\n", m2)

	fmt.Println(m.Cmp(m2))
}
