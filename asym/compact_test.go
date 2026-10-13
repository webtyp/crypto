package asym_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"webtyp.com/crypto/asym"
)

// The compact form is what JWS ES256 carries (RFC 7518 §3.4): exactly 64
// bytes, r||s, each left-padded to 32. A DER signature would not interoperate.
func TestSignCompactIs64Bytes(t *testing.T) {
	_, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ { // r or s with a leading zero byte must still pad to 32
		sig, err := asym.SignCompact([]byte("message"), priv)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 64 {
			t.Fatalf("SignCompact returned %d bytes, want 64", len(sig))
		}
	}
}

func TestCompactRoundTrip(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("header.payload")
	sig, err := asym.SignCompact(msg, priv)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := asym.VerifyCompact(msg, sig, pub)
	if err != nil || !ok {
		t.Fatalf("VerifyCompact(own signature) = %v, %v; want true, nil", ok, err)
	}
}

// A signature that does not verify is a verdict, not an error: the caller
// must be able to tell "this key is broken" (error) from "this token is
// forged" (false, nil).
func TestVerifyCompactRejectsWithoutError(t *testing.T) {
	pub, priv, _ := asym.GenerateKeyPair()
	otherPub, _, _ := asym.GenerateKeyPair()
	msg := []byte("header.payload")
	sig, _ := asym.SignCompact(msg, priv)

	tampered := append([]byte(nil), sig...)
	tampered[10] ^= 0xff

	cases := []struct {
		name string
		msg  []byte
		sig  []byte
		pub  []byte
	}{
		{"other key", msg, sig, otherPub},
		{"tampered signature", msg, tampered, pub},
		{"tampered message", []byte("header.payloaX"), sig, pub},
		{"short signature", msg, sig[:63], pub},
		{"long signature", msg, append(append([]byte(nil), sig...), 0), pub},
		{"all-zero signature", msg, make([]byte, 64), pub},
		{"DER signature", msg, mustDER(t, msg, priv), pub},
	}
	for _, c := range cases {
		ok, err := asym.VerifyCompact(c.msg, c.sig, c.pub)
		if ok || err != nil {
			t.Errorf("%s: VerifyCompact = %v, %v; want false, nil", c.name, ok, err)
		}
	}
}

// A key that is not a P-256 public key is the caller's problem: error.
func TestVerifyCompactRejectsBadKeys(t *testing.T) {
	sig := make([]byte, 64)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		key  []byte
	}{
		{"garbage", []byte("not a key")},
		{"empty", nil},
		{"P-384", p384DER},
	} {
		if _, err := asym.VerifyCompact([]byte("m"), sig, c.key); err == nil {
			t.Errorf("%s: VerifyCompact must return an error for a key that is not P-256", c.name)
		}
	}
}

func TestSignCompactRejectsBadKeys(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalECPrivateKey(p384)
	for _, c := range []struct {
		name string
		key  []byte
	}{
		{"garbage", []byte("not a key")},
		{"P-384", p384DER},
	} {
		if _, err := asym.SignCompact([]byte("m"), c.key); err == nil {
			t.Errorf("%s: SignCompact must return an error for a key that is not P-256", c.name)
		}
	}
}

func mustDER(t *testing.T, msg, priv []byte) []byte {
	t.Helper()
	der, err := asym.Sign(msg, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
