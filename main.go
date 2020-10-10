package main

import (
	"fmt"
	"math/big"

	"github.com/hima398/pairing-based-crypto/pairing"
)

func main() {
	pub, prv := pairing.GenerateKey(2048)

	m := big.NewInt(1)
	c := pairing.Encrypt(m, pub)

	m2 := pairing.Decrypt(c, prv)
	fmt.Printf("c = %v\n", c)
	fmt.Printf("m = %v\n", m2)

	fmt.Println(m.Cmp(m2))
}
