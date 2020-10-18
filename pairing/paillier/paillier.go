package paillier

import (
	"crypto"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/hima398/pairing-based-crypto/math"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// 公開鍵 (g, n)
type PublicKey struct {
	G *big.Int // random number
	N *big.Int // p * q
}

func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.N.Cmp(xx.N) == 0 && pub.G.Cmp(xx.G) == 0
}

func checkPub(pub *PublicKey) error {
	// TODO: modify
	return nil
}

// 秘密鍵 (p, q)
type PrivateKey struct {
	PublicKey          // public part.
	Lambda    *big.Int // lcm(p - 1, q - 1)
	Mu        *big.Int // L(g ^ lambda mod n ^ 2) ^ -1 mod n
}

func GenerateRandom(n *big.Int) *big.Int {
	buf := make([]byte, len(n.Bytes()))
	rand.Read(buf)
	return new(big.Int).Mod(new(big.Int).SetBytes(buf), n)
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	// TODO: modify
	return true
}

// GenerateKey generates an Paillier keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	p, _ := rand.Prime(random, bits/2)
	q, _ := rand.Prime(random, bits/2)

	// check p != q
	if p.Cmp(q) == 0 {
		return GenerateKey(random, bits)
	}
	// n = p * q
	n := new(big.Int).Mul(p, q)
	// n ^ 2
	n2 := new(big.Int).Mul(n, n)
	// lambda = lcm(p - 1, q - 1)
	lambda := math.LCM(new(big.Int).Sub(p, bigOne), new(big.Int).Sub(q, bigOne))

	g := new(big.Int)
	mu := new(big.Int)
	for {
		g = GenerateRandom(n2)
		// n^2と互いに素であるgを選択する
		if math.GCD(g, n2).Cmp(bigOne) != 0 {
			continue
		}

		// mu = 1 / ( L(g ^ lambda mod n ^ 2) )
		a := new(big.Int).Exp(g, lambda, n2)
		mu = L(a, n)
		if mu == nil {
			continue
		}
		if math.GCD(mu, n).Cmp(bigOne) != 0 {
			continue
		}
		// mu = L(g ^ lambda mod n ^ 2) ^ -1 mod n
		mu = new(big.Int).ModInverse(mu, n)
		// a ^ lambda = 1 (mod n)
		// gcd(L(g ^ lambda mod n ^ 2), n) = 1
		break
	}
	priv := new(PrivateKey)
	priv.Lambda = lambda
	priv.N = n
	priv.Mu = mu
	priv.PublicKey.N = n
	priv.PublicKey.G = g

	return priv, nil

}

func Encrypt(m *big.Int, pub *PublicKey) *big.Int {
	n2 := new(big.Int).Mul(pub.N, pub.N)
	// m:message
	// 0 <= m < n
	if m.Cmp(bigZero) <= 0 || m.Cmp(pub.N) > 0 {
		return nil
	}
	// nと互いに素なrを選択
	r := new(big.Int)
	for {
		r = GenerateRandom(pub.N)
		if math.GCD(r, pub.N).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		break
	}

	// 暗号文 c = g ^ m * r ^ n mod n ^ 2
	gm := new(big.Int).Exp(pub.G, m, n2)
	rn := new(big.Int).Exp(r, pub.N, n2)
	c := new(big.Int).Mod(new(big.Int).Mul(gm, rn), n2)
	return c
}

//
func (priv *PrivateKey) Decrypt(c *big.Int) *big.Int {

	n2 := new(big.Int).Mul(priv.N, priv.N)
	// 0 <= c < n ^ 2
	if c.Cmp(bigZero) <= 0 || c.Cmp(n2) > 0 {
		return nil
	}

	// m = ( L( c ^ lambda mod n ^ 2 ) / L( g ^ lambda mod n ^ 2 ) mod n )
	numerator := new(big.Int).Mod(L(new(big.Int).Exp(c, priv.Lambda, n2), priv.PublicKey.N), n2)
	m := new(big.Int).Mod(new(big.Int).Mul(numerator, priv.Mu), priv.PublicKey.N)
	return m
}

// L(u) = (u - 1) / n
func L(u, n *big.Int) *big.Int {
	numerator := new(big.Int).Sub(u, bigOne)
	if new(big.Int).Mod(numerator, n).Cmp(bigZero) != 0 {
		return nil
	}
	return new(big.Int).Div(numerator, n)
}
