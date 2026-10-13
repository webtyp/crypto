package asym

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"math/big"

	. "webtyp.com/fmt"
)

const (
	// compactHalf is the width of r and of s in a P-256 compact signature.
	compactHalf = 32
	// compactSize is the full r||s signature JWS ES256 carries (RFC 7518 §3.4).
	compactSize = 2 * compactHalf

	ErrNotP256Key = "not a P-256 key"
)

// SignCompact signs SHA-256(message) with an ECDSA P-256 private key (SEC 1
// DER, the format GenerateKeyPair returns) and returns the 64-byte r||s
// signature — each half left-padded to 32 bytes — that JWS ES256 uses
// (RFC 7518 §3.4). Sign returns ASN.1 DER instead, which is what WebAuthn
// uses; the two forms do not interoperate.
func SignCompact(message, privateKey []byte) ([]byte, error) {
	privKey, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if privKey.Curve != elliptic.P256() {
		return nil, Err(ErrNotP256Key)
	}

	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(randReader{}, privKey, hash[:])
	if err != nil {
		return nil, err
	}

	sig := make([]byte, compactSize)
	r.FillBytes(sig[:compactHalf])
	s.FillBytes(sig[compactHalf:])
	return sig, nil
}

// VerifyCompact verifies a 64-byte r||s signature over SHA-256(message) with
// a P-256 public key (PKIX/SPKI DER).
//
// The two return channels mean different things. err is non-nil exactly when
// publicKey is not a P-256 public key — the caller's configuration is
// broken. A signature that does not verify, including one of the wrong
// length, is (false, nil): a verdict on the signature, not an error.
func VerifyCompact(message, signature, publicKey []byte) (bool, error) {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, Err(ErrNotECDSAPublicKey)
	}
	if ecdsaPub.Curve != elliptic.P256() {
		return false, Err(ErrNotP256Key)
	}

	if len(signature) != compactSize {
		return false, nil
	}
	r := new(big.Int).SetBytes(signature[:compactHalf])
	s := new(big.Int).SetBytes(signature[compactHalf:])

	hash := sha256.Sum256(message)
	return ecdsa.Verify(ecdsaPub, hash[:], r, s), nil
}
