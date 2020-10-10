package pairing

import (
	"crypto/rand"
	"math/big"
)

// 公開鍵 (g, n)
type PublicKey struct {
	g *big.Int // random number
	n *big.Int // p * q
}

// 秘密鍵 (p, q)
type PrivateKey struct {
	lambda *big.Int // lcm(p - 1, q - 1)
	n      *big.Int // p * q
	mu     *big.Int // L(g ^ lambda mod n ^ 2) ^ -1 mod n
}

func GenerateRandom(n *big.Int) *big.Int {
	buf := make([]byte, len(n.Bytes()))
	rand.Read(buf)
	return new(big.Int).Mod(new(big.Int).SetBytes(buf), n)
}

func GenerateKey(bits int) (*PublicKey, *PrivateKey) {
	p, _ := rand.Prime(rand.Reader, bits/2)
	q, _ := rand.Prime(rand.Reader, bits/2)

	// check p != q
	if p.Cmp(q) == 0 {
		return GenerateKey(bits)
	}

	return CreateKey(p, q)
}

func CreateKey(p *big.Int, q *big.Int) (*PublicKey, *PrivateKey) {

	// n = p * q
	n := new(big.Int).Mul(p, q)
	// n ^ 2
	n2 := new(big.Int).Mul(n, n)
	// lambda = lcm(p - 1, q - 1)
	lambda := lcm(new(big.Int).Sub(p, ONE), new(big.Int).Sub(q, ONE))

	g := new(big.Int)
	mu := new(big.Int)
	for {
		g = GenerateRandom(n2)
		// n^2と互いに素であるgを選択する
		if gcd(g, n2).Cmp(ONE) != 0 {
			continue
		}

		// mu = 1 / ( L(g ^ lambda mod n ^ 2) )
		a := new(big.Int).Exp(g, lambda, n2)
		mu = L(a, n)
		if mu == nil {
			continue
		}
		if gcd(mu, n).Cmp(ONE) != 0 {
			continue
		}
		// mu = L(g ^ lambda mod n ^ 2) ^ -1 mod n
		mu = new(big.Int).ModInverse(mu, n)
		// a ^ lambda = 1 (mod n)
		// gcd(L(g ^ lambda mod n ^ 2), n) = 1
		break
	}
	pub := &PublicKey{n: n, g: g}
	prv := &PrivateKey{lambda: lambda, n: n, mu: mu}

	return pub, prv
}

func Encrypt(m *big.Int, pub *PublicKey) *big.Int {
	n2 := new(big.Int).Mul(pub.n, pub.n)
	// m:message
	// 0 <= m < n
	if m.Cmp(ZERO) <= 0 || m.Cmp(pub.n) > 0 {
		return nil
	}
	// nと互いに素なrを選択
	r := new(big.Int)
	for {
		r = GenerateRandom(pub.n)
		if gcd(r, pub.n).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		break
	}

	// 暗号文 c = g ^ m * r ^ n mod n ^ 2
	gm := new(big.Int).Exp(pub.g, m, n2)
	rn := new(big.Int).Exp(r, pub.n, n2)
	c := new(big.Int).Mod(new(big.Int).Mul(gm, rn), n2)
	return c
}

func Decrypt(c *big.Int, prv *PrivateKey) *big.Int {

	n2 := new(big.Int).Mul(prv.n, prv.n)
	// 0 <= c < n ^ 2
	if c.Cmp(ZERO) <= 0 || c.Cmp(n2) > 0 {
		return nil
	}

	// m = ( L( c ^ lambda mod n ^ 2 ) / L( g ^ lambda mod n ^ 2 ) mod n )
	numerator := new(big.Int).Mod(L(new(big.Int).Exp(c, prv.lambda, n2), prv.n), n2)
	m := new(big.Int).Mod(new(big.Int).Mul(numerator, prv.mu), prv.n)
	return m
}

// L(u) = (u - 1) / n
func L(u, n *big.Int) *big.Int {
	numerator := new(big.Int).Sub(u, big.NewInt(1))
	if new(big.Int).Mod(numerator, n).Cmp(ZERO) != 0 {
		return nil
	}
	return new(big.Int).Div(numerator, n)
}
