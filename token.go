package libtrust

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

func Base64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func Base64UrlDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 0:
	case 2:
		s = s + "=="
	case 3:
		s = s + "="
	default:
		return nil, ErrIllegalBase64Url
	}
	return base64.URLEncoding.DecodeString(s)
}

type Claim struct {
	Subject    string
	Action     string
	Expiration time.Time
}

func (c *Claim) Sign(id ID) (*Token, error) {
	protected := map[string]interface{}{
		"alg": "RS256",
		"jwk": id.JSONWebKey(),
	}
	//if chain != nil && len(chain) > 0 {
	//	arr := make([]string, len(chain))
	//	for i, t := range chain {
	//		arr[i] = t.String()
	//	}
	//	protected["jkc"] = arr
	//}

	claim := map[string]interface{}{
		"sub":    c.Subject,
		"action": c.Action,
		"exp":    c.Expiration.Unix(),
	}

	protectedBytes, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}

	claimBytes, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}

	claimString := Base64UrlEncode(claimBytes)
	protectedString := Base64UrlEncode(protectedBytes)

	buf := make([]byte, len(claimString)+len(protectedString)+1024)
	copy(buf, protectedString)
	buf[len(protectedString)] = '.'
	copy(buf[len(protectedString)+1:], claimString)
	signingByteLen := len(claimString) + len(protectedString) + 1

	sigBytes, err := id.Sign(bytes.NewReader(buf[:signingByteLen]))
	if err != nil {
		return nil, err
	}

	sigString := Base64UrlEncode(sigBytes)

	tokenLen := signingByteLen + len(sigString) + 1
	if len(buf) < tokenLen {
		newBuf := make([]byte, tokenLen)
		copy(newBuf, buf[:signingByteLen])
		buf = newBuf
	}
	buf[signingByteLen] = '.'
	copy(buf[signingByteLen+1:], sigString)

	return &Token{
		compact: buf[:tokenLen],
		issuer:  id,
		claim:   c,
	}, nil
}

type signedToken struct {
	tokenBytes []byte

	verified  bool
	claim     *Claim
	publicKey crypto.PublicKey
}

func (t *signedToken) String() string {
	return string(t.tokenBytes)
}

type Token struct {
	compact []byte

	claim    *Claim
	issuer   ID
	verifier ID

	Chain         []*Token
	VerifiedChain []*Token
}

type body map[string]interface{}

func parseBody(buf []byte) (body, int, error) {
	bodyLen := bytes.IndexByte(buf, '.')
	if bodyLen < 0 {
		return nil, 0, ErrIllegalTokenFormat
	}

	bodyBytes, err := Base64UrlDecode(string(buf[:bodyLen]))
	if err != nil {
		return nil, 0, err
	}

	body := make(map[string]interface{})
	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		return nil, 0, err
	}

	return body, bodyLen, nil
}

func verifySignature(header body, payload, signature []byte) (ID, error) {
	alg, ok := header["alg"]
	if !ok {
		return nil, ErrIllegalTokenFormat
	}

	sigBytes, err := Base64UrlDecode(string(signature))
	if err != nil {
		return nil, err
	}

	jwkHeader, ok := header["jwk"]
	if !ok {
		return nil, ErrMissingPublicKey
	}

	jwk, ok := jwkHeader.(map[string]interface{})
	if !ok {
		return nil, ErrIllegalTokenFormat
	}

	id, err := parseJSONWebKey(jwk)
	if err != nil {
		return nil, err
	}

	if alg == "RS256" {
		// Test compatibility
	} else {
		return nil, ErrUnsupportedAlgorithm
	}

	err = id.Verify(bytes.NewReader(payload), sigBytes)
	if err != nil {
		return nil, err
	}

	return id, nil
}

func parseJSONWebKey(jwk map[string]interface{}) (ID, error) {
	kty, ok := jwk["kty"]
	if !ok {
		return nil, ErrIllegalJWKFormat
	}

	switch kty {
	case "RSA":
		return parseRSAJWK(jwk)
	case "EC":
		return parseECJWK(jwk)
	default:
		return nil, ErrUnsupportedKeyType
	}

}

type parsedToken struct {
	header        body
	claim         body
	signer        ID
	nestedSigners []ID
}

func parseJWT(buf []byte) (*parsedToken, int, error) {
	header, headerlen, err := parseBody(buf)
	if err != nil {
		return nil, 0, err
	}
	if len(buf) <= headerlen+1 {
		return nil, 0, ErrIllegalTokenFormat
	}

	parsed := &parsedToken{header: header}
	var bodylen int
	if cty, ok := header["cty"]; ok {
		if ctys, ok := cty.(string); !ok || strings.ToLower(ctys) != "jwt" {
			// TODO specify illegal content type
			return nil, 0, ErrIllegalTokenFormat
		}

		// Parse nested JWT
		var nested *parsedToken
		nested, bodylen, err = parseJWT(buf[headerlen+1:])
		if err != nil {
			return nil, 0, err
		}
		if len(buf) <= headerlen+bodylen+2 || buf[headerlen+bodylen+1] != '.' {
			return nil, 0, ErrIllegalTokenFormat
		}

		parsed.claim = nested.claim
		parsed.nestedSigners = make([]ID, len(nested.nestedSigners)+1)
		parsed.nestedSigners[0] = nested.signer
		for i, k := range nested.nestedSigners {
			parsed.nestedSigners[i+1] = k
		}
	} else {
		// Parse claim body
		parsed.claim, bodylen, err = parseBody(buf[headerlen+1:])
		if err != nil {
			return nil, 0, err
		}
	}

	// Verify signature
	remaining := buf[headerlen+bodylen+2:]
	sigLen := bytes.IndexByte(remaining, '.')
	if sigLen < 0 {
		sigLen = len(remaining)
	}
	parsed.signer, err = verifySignature(header, buf[:headerlen+bodylen+1], remaining[:sigLen])
	if err != nil {
		return nil, 0, err
	}

	return parsed, headerlen + bodylen + sigLen + 2, nil
}

func ParseToken(token string) (*Token, error) {
	buf := []byte(token)

	parsed, l, err := parseJWT(buf)
	if err != nil {
		return nil, err
	}

	if len(buf) > l {
		return nil, ErrIllegalTokenFormat
	}

	claim := new(Claim)
	// Validate claims
	if subject, ok := parsed.claim["sub"]; ok {
		claim.Subject, ok = subject.(string)
		if !ok {
			return nil, ErrIllegalTokenFormat
		}
	} else {
		return nil, ErrIllegalTokenFormat
	}

	if action, ok := parsed.claim["action"]; ok {
		claim.Action, ok = action.(string)
		if !ok {
			return nil, ErrIllegalTokenFormat
		}
	} else {
		return nil, ErrIllegalTokenFormat
	}

	if expiration, ok := parsed.claim["exp"]; ok {
		sec, ok := expiration.(float64)
		if !ok {
			return nil, ErrIllegalTokenFormat
		}
		claim.Expiration = time.Unix(int64(sec), 0)
	} else {
		return nil, ErrIllegalTokenFormat
	}

	if len(parsed.nestedSigners) > 1 {
		// Only one nested key supported
		return nil, ErrIllegalTokenFormat
	}

	// TODO check chains, call ParseToken, aggregate chain

	ret := &Token{
		compact: buf,

		claim: claim,

		//Chain         []*Token
		//VerifiedChain []*Token
	}

	if len(parsed.nestedSigners) == 1 {
		ret.issuer = parsed.nestedSigners[0]
		ret.verifier = parsed.signer
	} else {
		ret.issuer = parsed.signer
	}

	return ret, nil
}

func (t Token) Verified() bool {
	return false
}

// Verify a token by either using the chain trust
// in a nested token or checking against the local
// or remote trust graph
func (t *Token) Verify() error {
	// Check chain of trust
	return ErrInvalidSignature
}

func (t *Token) Sign(id ID) (*Token, error) {
	protected := map[string]interface{}{
		"alg": "RS256",
		"jwk": id.JSONWebKey(),
		"cty": "JWT",
	}
	//if chain != nil && len(chain) > 0 {
	//	arr := make([]string, len(chain))
	//	for i, t := range chain {
	//		arr[i] = t.String()
	//	}
	//	protected["jkc"] = arr
	//}

	protectedBytes, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}

	protectedString := Base64UrlEncode(protectedBytes)

	buf := make([]byte, len(t.compact)+len(protectedString)+1024)
	copy(buf, protectedString)
	buf[len(protectedString)] = '.'
	copy(buf[len(protectedString)+1:], t.compact)
	signingByteLen := len(t.compact) + len(protectedString) + 1

	sigBytes, err := id.Sign(bytes.NewReader(buf[:signingByteLen]))
	if err != nil {
		return nil, err
	}

	sigString := Base64UrlEncode(sigBytes)

	tokenLen := signingByteLen + len(sigString) + 1
	if len(buf) < tokenLen {
		newBuf := make([]byte, tokenLen)
		copy(newBuf, buf[:signingByteLen])
		buf = newBuf
	}
	buf[signingByteLen] = '.'
	copy(buf[signingByteLen+1:], sigString)

	return &Token{
		compact:  buf[:tokenLen],
		issuer:   t.issuer,
		verifier: id,
		claim:    t.claim,
	}, nil

	return nil, nil
}

func (t *Token) Authorized(action, subject string) bool {
	if t.VerifiedChain == nil {
		return false
	}

	if !strings.HasPrefix(strings.ToLower(subject), t.claim.Subject) {
		return false
	}

	if strings.ToLower(action) != strings.ToLower(t.claim.Action) {
		return false
	}

	if t.claim.Expiration.After(time.Now().Add(-15 * time.Second)) {
		return false
	}

	return true
}

func (t *Token) String() string {
	return string(t.compact)
}
