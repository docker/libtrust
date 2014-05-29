package libtrust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

var ErrUnsupportedKeyType = errors.New("unsupported key type")

// Whether tls will check the servers certificate against root CAs
var InsecureTLS bool

// Used to create a trusted connection to a server
type TrustedDialer struct {
	Id

	tlsConfig *tls.Config
}

func NewTrustedDialer(id Id) (*TrustedDialer, error) {
	d := new(TrustedDialer)
	d.Id = id

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			Organization: []string{"libtrust"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	pubKey, privKey := id.Keys()
	certDer, certErr := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)

	if certErr != nil {
		return nil, certErr
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	rsaKey, rsaKeyOk := privKey.(*rsa.PrivateKey)
	if !rsaKeyOk {
		return nil, ErrUnsupportedKeyType
	}
	keyDer := x509.MarshalPKCS1PrivateKey(rsaKey)
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDer})

	tlsCert, tlsCertErr := tls.X509KeyPair(cert, key)

	if tlsCertErr != nil {
		return nil, tlsCertErr
	}

	d.tlsConfig = new(tls.Config)
	d.tlsConfig.InsecureSkipVerify = InsecureTLS
	d.tlsConfig.Certificates = []tls.Certificate{tlsCert}

	return d, nil
}

func (d *TrustedDialer) Dial(network, address string) (net.Conn, error) {
	return tls.Dial(network, address, d.tlsConfig)
}
