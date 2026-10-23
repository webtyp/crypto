// Package rsasig verifies RSA signatures of the kind JWT calls RS256:
// RSASSA-PKCS1-v1_5 with SHA-256. Verification only — this ecosystem never
// signs with RSA; it only checks tokens a third party (e.g. Cloudflare
// Access) signed.
//
// On native targets (!wasm), it delegates to crypto/rsa and crypto/sha256.
// On WASM targets (wasm), it delegates to the host Web Crypto API (SubtleCrypto)
// via syscall/js, keeping math/big and crypto/rsa out of the WASM binary.
//
// Example:
//
//	ok, err := rsasig.VerifySHA256(rsasig.PublicKey{N: n, E: e}, []byte(signingInput), sig)
//	if err != nil { /* the key itself is unusable: a configuration problem */ }
//	if !ok { /* forged or tampered */ }
package rsasig

import (
	"webtyp.com/fmt"
)

// ErrMsgInvalidPublicKey is returned when the key cannot be used at all: a
// modulus shorter than MinModulusBits, or an exponent that is empty, longer
// than 4 bytes, smaller than 3 or even.
const ErrMsgInvalidPublicKey = "rsasig: invalid public key"

// MinModulusBits is the smallest modulus accepted. Keys below 2048 bits are
// breakable and are refused instead of verified.
const MinModulusBits = 2048

// maxExponentBytes keeps the exponent inside an int on every platform.
const maxExponentBytes = 4

// minExponent is the smallest valid RSA public exponent.
const minExponent = 3

// PublicKey is an RSA public key as a JWK carries it (RFC 7518 §6.3.1):
// N is the modulus and E the public exponent, both unsigned big-endian
// bytes (already base64url-decoded).
//
// Example: PublicKey{N: modulusBytes, E: []byte{0x01, 0x00, 0x01}} // e = 65537
type PublicKey struct {
	N []byte
	E []byte
}

// VerifySHA256 reports whether signature is a valid RSASSA-PKCS1-v1_5
// SHA-256 signature of message under pub.
//
// Two channels, never mixed: error != nil means the KEY is unusable (the
// caller's configuration); false with a nil error means the signature does
// not match (forged, tampered, or signed by another key).
//
// Example:
//
//	ok, err := rsasig.VerifySHA256(key, []byte("header.payload"), sig)
func VerifySHA256(pub PublicKey, message, signature []byte) (bool, error) {
	if err := validateKey(pub); err != nil {
		return false, err
	}
	return verifySignature(pub, message, signature)
}

func validateKey(pub PublicKey) error {
	if bitLen(pub.N) < MinModulusBits {
		return fmt.Err(ErrMsgInvalidPublicKey)
	}
	if len(pub.E) == 0 || len(pub.E) > maxExponentBytes {
		return fmt.Err(ErrMsgInvalidPublicKey)
	}
	e := 0
	for _, b := range pub.E {
		e = e<<8 | int(b)
	}
	if e < minExponent || e%2 == 0 {
		return fmt.Err(ErrMsgInvalidPublicKey)
	}
	return nil
}

func bitLen(b []byte) int {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	bits := len(b) * 8
	top := b[0]
	for top < 0x80 {
		bits--
		top <<= 1
	}
	return bits
}

func bitLen(b []byte) int {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	bits := len(b) * 8
	top := b[0]
	for top < 0x80 {
		bits--
		top <<= 1
	}
	return bits
}

