package tests

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"webtyp.com/crypto/rsasig"
)

func pubOf(priv *rsa.PrivateKey) rsasig.PublicKey {
	return rsasig.PublicKey{
		N: priv.N.Bytes(),
		E: big.NewInt(int64(priv.E)).Bytes(),
	}
}

func TestVerifyValid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	msg := []byte("a.b")
	digest := crypto.SHA256.New()
	digest.Write(msg)
	hashed := digest.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	ok, err := rsasig.VerifySHA256(pubOf(priv), msg, sig)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if !ok {
		t.Error("expected ok=true, got false")
	}
}

func TestVerifyTamperedMessage(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	msg := []byte("a.b")
	digest := crypto.SHA256.New()
	digest.Write(msg)
	hashed := digest.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	ok, err := rsasig.VerifySHA256(pubOf(priv), []byte("a.c"), sig)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if ok {
		t.Error("expected ok=false for tampered message, got true")
	}
}

func TestVerifyOtherKey(t *testing.T) {
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	msg := []byte("a.b")
	digest := crypto.SHA256.New()
	digest.Write(msg)
	hashed := digest.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv1, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	ok, err := rsasig.VerifySHA256(pubOf(priv2), msg, sig)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if ok {
		t.Error("expected ok=false for other key, got true")
	}
}

func TestVerifyTruncatedSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	msg := []byte("a.b")
	digest := crypto.SHA256.New()
	digest.Write(msg)
	hashed := digest.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	ok, err := rsasig.VerifySHA256(pubOf(priv), msg, sig[:len(sig)-1])
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if ok {
		t.Error("expected ok=false for truncated signature, got true")
	}
}

func TestRejectShortModulus(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	ok, err := rsasig.VerifySHA256(pubOf(priv), []byte("msg"), []byte("sig"))
	if ok {
		t.Error("expected ok=false for short modulus")
	}
	if err == nil || err.Error() != rsasig.ErrMsgInvalidPublicKey {
		t.Errorf("expected error %q, got %v", rsasig.ErrMsgInvalidPublicKey, err)
	}
}

func TestRejectBadExponent(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	tests := []struct {
		name string
		e    []byte
	}{
		{"empty", []byte{}},
		{"even", []byte{2}},
		{"too long", []byte{1, 2, 3, 4, 5}},
		{"smaller than 3", []byte{1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub := pubOf(priv)
			pub.E = tc.e

			ok, err := rsasig.VerifySHA256(pub, []byte("msg"), []byte("sig"))
			if ok {
				t.Error("expected ok=false")
			}
			if err == nil || err.Error() != rsasig.ErrMsgInvalidPublicKey {
				t.Errorf("expected error %q, got %v", rsasig.ErrMsgInvalidPublicKey, err)
			}
		})
	}
}
