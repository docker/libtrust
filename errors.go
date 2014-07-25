package libtrust

import (
	"errors"
)

var (
	ErrIllegalJWKFormat     = errors.New("Illegal JSON web key format")
	ErrIllegalBase64Url     = errors.New("Illegal base64url string")
	ErrIllegalTokenFormat   = errors.New("Illegal token format")
	ErrMissingSignature     = errors.New("Missing signature")
	ErrMissingPublicKey     = errors.New("Missing public key")
	ErrInvalidSignature     = errors.New("Invalid signature")
	ErrUnsupportedAlgorithm = errors.New("Unsupported algorithm")
	ErrUnsupportedKeyType   = errors.New("Unsupported key type")
	ErrUnsupportedOperation = errors.New("Unsupported operation")
)
