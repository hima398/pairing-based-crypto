package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader, 2048)

	m := bigOne

	c := Encrypt(m, &priv.PublicKey)
	m2 := priv.Decrypt(c)

	if m.Cmp(m2) != 0 {
		t.Errorf("actual %v\nexpected %v", m2, m)
	}
}

func TestEncrypt(t *testing.T) {

	// 平文の準同型加法
	t.Run("Homomorphic addition of plaintexts", func(t *testing.T) {
		//
		key, _ := GenerateKey(rand.Reader, 2048)

		m1 := big.NewInt(3)
		m2 := big.NewInt(5)

		c1 := Encrypt(m1, &key.PublicKey)
		c2 := Encrypt(m2, &key.PublicKey)

		n2 := new(big.Int).Mul(key.PublicKey.N, key.PublicKey.N)
		actual := key.Decrypt(new(big.Int).Mod(new(big.Int).Mul(c1, c2), n2))
		expected := big.NewInt(8)

		if actual.Cmp(expected) != 0 {
			t.Errorf("actual %s, expected %s", actual, expected)
		}
	})

	// 平文の準同型乗法
	t.Run("Homomorphic multiplication of plaintexts", func(t *testing.T) {
		key, _ := GenerateKey(rand.Reader, 2048)

		m1 := big.NewInt(3)
		m2 := big.NewInt(5)

		c1 := Encrypt(m1, &key.PublicKey)
		c2 := Encrypt(m2, &key.PublicKey)

		n2 := new(big.Int).Mul(key.PublicKey.N, key.PublicKey.N)
		d1 := key.Decrypt(new(big.Int).Exp(c1, m2, n2))
		expected := big.NewInt(15)

		if d1.Cmp(expected) != 0 {
			t.Errorf("actual %s, expected %s", d1, expected)
		}

		d2 := key.Decrypt(new(big.Int).Exp(c2, m1, n2))

		if d2.Cmp(expected) != 0 {
			t.Errorf("actual %s, expected %s", d2, expected)
		}
	})

}
