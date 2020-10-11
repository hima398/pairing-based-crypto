package math

import (
	"math/big"
)

// greatest common divisor
func GCD(a, b *big.Int) *big.Int {
	x := new(big.Int)
	y := new(big.Int)
	return new(big.Int).GCD(x, y, a, b)
}

// least common multiple
func LCM(a, b *big.Int) *big.Int {
	// a * b / gcd(a, b)
	return new(big.Int).Div(new(big.Int).Mul(a, b), GCD(a, b))
}
