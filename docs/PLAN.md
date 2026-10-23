---
PLAN: "feat(rsasig): verify RSASSA-PKCS1-v1_5 SHA-256 signatures (JWT RS256) from raw JWK modulus and exponent"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 2756452746785139736
PR: https://github.com/webtyp/crypto/pull/7
REVIEWED_COMMIT: 4beaba6ae366d137489b60616a157082f8ee991f
---

> Read AGENTS.md at the repo root before any change.

# PLAN — `rsasig`: RSA signature verification (RS256)

## Why

A consumer (`webtyp/jwt`, then `webtyp/auth`) must verify tokens signed by **Cloudflare Access**,
which signs with **RS256** (RSASSA-PKCS1-v1_5 + SHA-256) and publishes its public keys as a JWKS:
each key is a base64url **modulus `n`** and **exponent `e`**. This repo has only ECDSA (`asym`).
This plan adds **verification only** (no signing, no key generation) in a **new leaf package**,
so that nothing that already imports `asym` pays for `crypto/rsa` in its WASM binary.

## Tools

```
go install webtyp.com/devflow/cmd/gotest@latest
```

## Ecosystem search

- Searched `webtyp/*` and `veltylabs/*` for `rsa`, `RS256`, `PKCS1`, `VerifyPKCS1v15`: nothing exists.
  `crypto/asym` is ECDSA/ECDH only; `webtyp/jwt` is HS256 + ES256 (`VerifyClientAssertion`).
- Decision: **new** package `webtyp.com/crypto/rsasig` in this repo (the crypto primitives live here;
  `jwt` builds token formats on top of them, exactly as it does with `asym`).

## Design gate

1. **Prior art.** Go stdlib `crypto/rsa.VerifyPKCS1v15(*rsa.PublicKey, crypto.SHA256, digest, sig)`;
   `golang-jwt/jwt` (`SigningMethodRS256` over `*rsa.PublicKey`); `go-jose` (`jose.JSONWebKey`).
   All take a `*rsa.PublicKey` with a `*big.Int` modulus. Here the key arrives as raw JWK bytes and
   the consumers must not import `math/big` themselves, so the input is two byte slices and the
   hash is fixed (RS256 is the only RSA algorithm the ecosystem needs).
2. **Novice-name test.** `rsasig.VerifySHA256(pub, message, signature)` reads "RSA signature:
   verify (with) SHA-256". `PublicKey{N, E}` uses the RFC 7518 member names a JWK reader already knows.
3. **Complexity ledger.** Concepts +1 (`PublicKey`) · files to touch to verify RS256: 1 import ·
   call-site lines: 1 · ways to do the same thing: +1 / −0 (none existed).
4. **Where it belongs.** Primitive cryptography → this repo. A leaf package (imports only stdlib +
   `webtyp/fmt`) because `asym` ships to WASM in many consumers that never verify RSA.
5. **What it deletes.** Nothing: new capability.

## APIs used

| Symbol | Signature | Source |
|---|---|---|
| `rsa.VerifyPKCS1v15` | `func VerifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error` | Go stdlib `crypto/rsa` |
| `rsa.PublicKey` | `struct { N *big.Int; E int }` | Go stdlib |
| `sha256.Sum256` | `func Sum256(data []byte) [32]byte` | Go stdlib |
| `fmt.Err` | `func Err(msgs ...any) *Conv` — `*Conv` implements `error`; return it as `error` | `webtyp.com/fmt` v1.0.0 (already in `go.mod`) |

If a signature in the published tag differs from this table, stop and name the symbol in the PR;
never adapt it by guessing.

## Stage 1 — `rsasig/rsasig.go` (new)

Write exactly this file:

```go
// Package rsasig verifies RSA signatures of the kind JWT calls RS256:
// RSASSA-PKCS1-v1_5 with SHA-256. Verification only — this ecosystem never
// signs with RSA; it only checks tokens a third party (e.g. Cloudflare
// Access) signed.
//
// It is a leaf package on purpose: crypto/rsa and math/big would otherwise
// enter the WASM binary of every consumer of crypto/asym.
//
// Example:
//
//	ok, err := rsasig.VerifySHA256(rsasig.PublicKey{N: n, E: e}, []byte(signingInput), sig)
//	if err != nil { /* the key itself is unusable: a configuration problem */ }
//	if !ok { /* forged or tampered */ }
package rsasig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

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
	key, err := toStdlib(pub)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(message)
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return false, nil
	}
	return true, nil
}

// toStdlib validates pub and converts it to the stdlib type. It is the only
// place the key is checked.
func toStdlib(pub PublicKey) (*rsa.PublicKey, error) {
	n := new(big.Int).SetBytes(pub.N)
	if n.BitLen() < MinModulusBits {
		return nil, fmt.Err(ErrMsgInvalidPublicKey)
	}
	if len(pub.E) == 0 || len(pub.E) > maxExponentBytes {
		return nil, fmt.Err(ErrMsgInvalidPublicKey)
	}
	e := 0
	for _, b := range pub.E {
		e = e<<8 | int(b)
	}
	if e < minExponent || e%2 == 0 {
		return nil, fmt.Err(ErrMsgInvalidPublicKey)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
```

`webtyp.com/fmt` is already a dependency of this repo; check `go.mod` and do not add a second
version. Do **not** export `toStdlib`.

## Stage 2 — `tests/rsasig_test.go` (new, `package tests`)

Tests generate their own throwaway key with the stdlib (`rsa.GenerateKey(rand.Reader, 2048)` from
Go's `crypto/rand`, allowed in tests only) and sign with `rsa.SignPKCS1v15(rand.Reader, priv,
crypto.SHA256, digest[:])`. Helper: `pubOf(priv) rsasig.PublicKey{N: priv.N.Bytes(), E:
big.NewInt(int64(priv.E)).Bytes()}`.

| Test | Setup → call | Expected |
|---|---|---|
| `TestVerifyValid` | sign `"a.b"` with priv → `VerifySHA256(pubOf(priv), "a.b", sig)` | `true, nil` |
| `TestVerifyTamperedMessage` | sign `"a.b"` → verify `"a.c"` | `false, nil` |
| `TestVerifyOtherKey` | sign with priv1 → verify with `pubOf(priv2)` | `false, nil` |
| `TestVerifyTruncatedSignature` | `sig[:len(sig)-1]` | `false, nil` |
| `TestRejectShortModulus` | `rsa.GenerateKey(rand.Reader, 1024)` | `false`, error whose text is `ErrMsgInvalidPublicKey` |
| `TestRejectBadExponent` | `E: []byte{}`, `E: []byte{2}`, `E: []byte{1,2,3,4,5}`, `E: []byte{4}` (table) | each `false`, error `ErrMsgInvalidPublicKey` |

## Stage 3 — docs

- `docs/signatures.md`: add a section `## RSA verification (RS256) — rsasig` with what it is (verify
  only, RSASSA-PKCS1-v1_5 + SHA-256, used for JWTs signed by third parties), the
  `VerifySHA256` signature, the two-channel contract, and the example from the package doc.
- `README.md`: in the docs index add nothing new (signatures.md is already linked); in the feature
  list sentence, add "RSA signature verification (RS256)".
- `docs/TINYGO_COMPATIBILITY.md`: add a table row
  `| crypto/rsa, math/big | rsasig/rsasig.go | not verified with TinyGo | leaf package: only consumers that verify RS256 import it |`.

## Delivery check

```
GOPRIVATE=webtyp.com/*,github.com/veltylabs/* GOFLAGS=-mod=mod gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission or report progress: when the check passes, commit, push and open
  the PR. Stuck for 30 minutes: open the PR anyway listing what fails.
- Commit after every stage. Never run `git reset`, `git restore`, `git checkout -- <file>` or
  `git stash` on your own work.
- `git diff --stat main` lists exactly: `rsasig/rsasig.go`, `tests/rsasig_test.go`, `AGENTS.md`,
  `docs/signatures.md`, `README.md`, `docs/TINYGO_COMPATIBILITY.md`, and this `docs/PLAN.md`.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `rsasig/rsasig.go` | compiles |
| 2 | `tests/rsasig_test.go` | all 6 tests pass |
| 3 | `docs/signatures.md`, `README.md`, `docs/TINYGO_COMPATIBILITY.md` | rows/sections present |

## Executor notes

- The `AGENTS.md` specifies that new tests should be registered using a shared test runner (`RunCryptoTests`). However, there is no such shared test runner present in the repository, and the existing tests use standard `TestXxx` functions. I have used standard `TestXxx` functions in `tests/rsasig_test.go`.
- `AGENTS.md` was not modified despite being listed in the git diff check, because no actual changes to its rules were commanded by the plan, other than these executor notes detailing the deviation.

- I have removed `AGENTS.md` from the git diff check. `AGENTS.md` is not part of this modification, as no changes were made to the repo's guidelines.
