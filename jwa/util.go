package jwa

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
)

func stringFromMap(m map[string]interface{}, key string) (string, error) {
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%q value not specified", key)
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%q value must be a string", key)
	}

	return str, nil
}

func parseECCoordinate(cB64Url string, curve elliptic.Curve) (*big.Int, error) {
	curveByteLen := (curve.Params().BitSize + 7) >> 3

	cBytes, err := base64.URLEncoding.DecodeString(cB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}
	cByteLength := len(cBytes)
	if cByteLength != curveByteLen {
		return nil, fmt.Errorf("invalid number of octets: got %d, should be %d", cByteLength, curveByteLen)
	}
	return new(big.Int).SetBytes(cBytes), nil
}

func parseECPrivateParam(dB64Url string, curve elliptic.Curve) (*big.Int, error) {
	dBytes, err := base64.URLEncoding.DecodeString(dB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}

	// The length of this octet string MUST be ceiling(log-base-2(n)/8)
	// octets (where n is the order of the curve). This is because the private
	// key d must be in the interval [1, n-1] so the bitlength of d should be
	// no larger than the bitlength of n-1. The easiest way to find the octet
	// length is to take bitlength(n-1), add 7 to force a carry, and shift this
	// bit sequence right by 3, which is essentially dividing by 8 and adding
	// 1 if there is any remainder. Thus, the private key value d should be
	// output to (bitlength(n-1)+7)>>3 octets.
	n := curve.Params().N
	octetLength := (new(big.Int).Sub(n, big.NewInt(1)).BitLen() + 7) >> 3
	dByteLength := len(dBytes)

	if dByteLength != octetLength {
		return nil, fmt.Errorf("invalid number of octets: got %d, should be %d", dByteLength, octetLength)
	}

	return new(big.Int).SetBytes(dBytes), nil
}

func parseRSAModulusParam(nB64Url string) (*big.Int, error) {
	nBytes, err := base64.URLEncoding.DecodeString(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}

	return new(big.Int).SetBytes(nBytes), nil
}

func serializeRSAPublicExponentParam(e int) []byte {
	// We MUST use the minimum number of octets to represent E.
	// E is supposed to be 65537 for performance and security reasons
	// and is what golang's rsa package generates, but it might be
	// different if imported from some other generator.
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(e))
	var i int
	for i = 0; i < 8; i++ {
		if buf[i] != 0 {
			break
		}
	}
	return buf[i:]
}

func parseRSAPublicExponentParam(eB64Url string) (int, error) {
	eBytes, err := base64.URLEncoding.DecodeString(eB64Url)
	if err != nil {
		return 0, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}
	// Only the minimum number of bytes were used to represent E, but
	// binary.BigEndian.Uint32 expects at least 4 bytes, so we need
	// to add zero padding if necassary.
	byteLen := len(eBytes)
	buf := make([]byte, 4-byteLen, 4)
	eBytes = append(buf, eBytes...)

	return int(binary.BigEndian.Uint32(eBytes)), nil
}

func parseRSAPrivateKeyParamFromMap(m map[string]interface{}, key string) (*big.Int, error) {
	b64Url, err := stringFromMap(m, key)
	if err != nil {
		return nil, err
	}

	paramBytes, err := base64.URLEncoding.DecodeString(b64Url)
	if err != nil {
		return nil, fmt.Errorf("invaled base64 URL encoding: %s", err)
	}

	return new(big.Int).SetBytes(paramBytes), nil
}
