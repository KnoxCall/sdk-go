package knoxcall

// DPoP proof generation (RFC 9449) — client side. Go port of
// knoxcall-node/src/auth/dpop.ts and knoxcall-python .../auth/dpop.py
// (see ../../PARITY.md §7).
//
// Generates an ES256 (P-256) keypair and signs a fresh proof JWT per
// request. Stdlib only — no external JWT dependency. The private key never
// leaves the process.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// dpopJwk is the public JWK embedded in proof headers. Field order matches
// the RFC 7638 canonical member order (crv, kty, x, y), so marshaling the
// same struct serves both the proof header and the thumbprint input.
type dpopJwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dpopKeyPair struct {
	privateKey *ecdsa.PrivateKey
	publicJwk  dpopJwk
}

func generateDpopKeyPair() (*dpopKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("knoxcall: generate DPoP keypair: %w", err)
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.PublicKey.X.FillBytes(x)
	key.PublicKey.Y.FillBytes(y)
	return &dpopKeyPair{
		privateKey: key,
		publicJwk:  dpopJwk{Crv: "P-256", Kty: "EC", X: b64url(x), Y: b64url(y)},
	}, nil
}

// sign builds a DPoP proof JWT for one request (RFC 9449 §4.2): fresh jti and
// iat on every call, htu stripped of query and fragment, ath bound to the
// access token when one is being presented. The signature is ECDSA P-256 +
// SHA-256 in JOSE P1363 form (r||s, 64 bytes), matching the server verifier
// in src/lib/dpop-verifier.ts.
func (kp *dpopKeyPair) sign(method, rawURL, accessToken, nonce string) (string, error) {
	htu := rawURL
	if i := strings.IndexByte(htu, '#'); i >= 0 {
		htu = htu[:i]
	}
	if i := strings.IndexByte(htu, '?'); i >= 0 {
		htu = htu[:i]
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("knoxcall: DPoP jti: %w", err)
	}

	header := struct {
		Alg string  `json:"alg"`
		Typ string  `json:"typ"`
		Jwk dpopJwk `json:"jwk"`
	}{Alg: "ES256", Typ: "dpop+jwt", Jwk: kp.publicJwk}
	payload := map[string]any{
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": b64url(jti),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = b64url(sum[:])
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64url(headerJSON) + "." + b64url(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, kp.privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("knoxcall: sign DPoP proof: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64url(sig), nil
}

// thumbprint is the RFC 7638 JWK thumbprint of the public key — the value
// the server binds tokens to as cnf.jkt. Canonical form is the JSON object
// with exactly the members crv, kty, x, y in that order, which is what
// marshaling dpopJwk produces.
func (kp *dpopKeyPair) thumbprint() (string, error) {
	canonical, err := json.Marshal(kp.publicJwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return b64url(sum[:]), nil
}
