package paillier

import (
	"crypto/rand"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader, 2048)

	m := bigOne

	c := Encrypt(m, &priv.PublicKey)
	m2 := priv.Decrypt(c, priv)

	if m.Cmp(m2) != 0 {
		t.Errorf("actual %v\nexpected %v", m2, m)
	}
}
