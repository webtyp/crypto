//go:build wasm

package rsasig

import (
	"syscall/js"

	"webtyp.com/base64"
	"webtyp.com/fmt"
)

func verifySignature(pub PublicKey, message, signature []byte) (bool, error) {
	cryptoObj := js.Global().Get("crypto")
	if cryptoObj.IsNull() || cryptoObj.IsUndefined() {
		return false, fmt.Err("rsasig: crypto Web API unavailable")
	}
	subtle := cryptoObj.Get("subtle")
	if subtle.IsNull() || subtle.IsUndefined() {
		return false, fmt.Err("rsasig: crypto.subtle Web API unavailable")
	}

	jwk := js.Global().Get("Object").New()
	jwk.Set("kty", "RSA")
	jwk.Set("n", base64.URLEncode(pub.N))
	jwk.Set("e", base64.URLEncode(pub.E))
	jwk.Set("alg", "RS256")
	jwk.Set("ext", true)

	algo := js.Global().Get("Object").New()
	algo.Set("name", "RSASSA-PKCS1-v1_5")
	algo.Set("hash", "SHA-256")

	usages := js.Global().Get("Array").New(1)
	usages.SetIndex(0, "verify")

	keyPromise := subtle.Call("importKey", "jwk", jwk, algo, false, usages)
	keyVal, err := awaitPromise(keyPromise)
	if err != nil {
		return false, fmt.Err("rsasig: importKey failed:", err)
	}

	sigArr := uint8ArrayOf(signature)
	msgArr := uint8ArrayOf(message)

	verifyPromise := subtle.Call("verify", "RSASSA-PKCS1-v1_5", keyVal, sigArr, msgArr)
	resultVal, err := awaitPromise(verifyPromise)
	if err != nil {
		// SubtleCrypto rejects if the signature length is invalid
		return false, nil
	}
	return resultVal.Bool(), nil
}

func uint8ArrayOf(b []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(arr, b)
	return arr
}

func awaitPromise(promise js.Value) (js.Value, error) {
	resultCh := make(chan js.Value, 1)
	errCh := make(chan error, 1)

	var onOk, onFail js.Func
	onOk = js.FuncOf(func(_ js.Value, args []js.Value) any {
		var val js.Value
		if len(args) > 0 {
			val = args[0]
		}
		resultCh <- val
		return nil
	})
	defer onOk.Release()

	onFail = js.FuncOf(func(_ js.Value, args []js.Value) any {
		msg := "promise rejected"
		if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
			msg = args[0].Call("toString").String()
		}
		errCh <- fmt.Err(msg)
		return nil
	})
	defer onFail.Release()

	promise.Call("then", onOk).Call("catch", onFail)
	select {
	case v := <-resultCh:
		return v, nil
	case err := <-errCh:
		return js.Undefined(), err
	}
}
