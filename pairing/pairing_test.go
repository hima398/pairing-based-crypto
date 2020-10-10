package pairing

import (
	"testing"
)

func TestGenerateKey(t *testing.T) {
	pub, prv := GenerateKey(2048)

	m := ONE

	c := Encrypt(m, pub)
	m2 := Decrypt(c, prv)

	if m.Cmp(m2) != 0 {
		t.Errorf("actual %v\nexpected %v", m2, m)
	}
}
