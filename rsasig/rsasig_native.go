//go:build !wasm

package rsasig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
)

func verifySignature(pub PublicKey, message, signature []byte) (bool, error) {
	n := new(big.Int).SetBytes(pub.N)
	e := 0
	for _, b := range pub.E {
		e = e<<8 | int(b)
	}
	key := &rsa.PublicKey{N: n, E: e}
	digest := sha256.Sum256(message)
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return false, nil
	}
	return true, nil
}
