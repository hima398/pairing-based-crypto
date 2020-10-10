package pairing

import (
	"math/big"
)

var ZERO = big.NewInt(0)
var ONE = big.NewInt(1)

// greatest common divisor
func gcd(a, b *big.Int) *big.Int {
	x := new(big.Int)
	y := new(big.Int)
	return new(big.Int).GCD(x, y, a, b)
}

// least common multiple
func lcm(a, b *big.Int) *big.Int {
	// a * b / gcd(a, b)
	return new(big.Int).Div(new(big.Int).Mul(a, b), gcd(a, b))
}
