package libtrust

import (
	"crypto"
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
var RootCAs *x509.CertPool

// Used to create a trusted connection to a server
type TrustedDialer struct {
	id Id

	tlsConfig *tls.Config
}

type TrustedConn struct {
	conn *tls.Conn
	id   Id
}

func NewTrustedDialer(id Id) (*TrustedDialer, error) {
	d := new(TrustedDialer)
	d.id = id

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
	d.tlsConfig.RootCAs = RootCAs

	return d, nil
}

func (d *TrustedDialer) Dial(network, address string) (*TrustedConn, error) {
	tlsConn, tlsErr := tls.Dial(network, address, d.tlsConfig)
	if tlsErr != nil {
		return nil, tlsErr
	}
	return &TrustedConn{conn: tlsConn, id: d.id}, nil
}

// Implement net.Conn interface
func (c *TrustedConn) Read(b []byte) (int, error)         { return c.conn.Read(b) }
func (c *TrustedConn) Write(b []byte) (int, error)        { return c.conn.Write(b) }
func (c *TrustedConn) Close() error                       { return c.conn.Close() }
func (c *TrustedConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *TrustedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *TrustedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *TrustedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *TrustedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *TrustedConn) Id() Id {
	return c.id
}

type TrustedServer struct {
	tlsConfig *tls.Config
}

func NewTrustedServer(c *tls.Config) *TrustedServer {
	return &TrustedServer{
		tlsConfig: c,
	}
}

func (ts *TrustedServer) Listen(network, address string) (net.Listener, error) {
	listener, err := tls.Listen(network, address, ts.tlsConfig)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func (ts *TrustedServer) Authenticate(conn net.Conn) (crypto.PublicKey, error) {
	var tlsConn *tls.Conn
	switch c := conn.(type) {
	case *tls.Conn:
		tlsConn = c
	default:
		tlsConn = tls.Server(conn, ts.tlsConfig)
	}

	tlsErr := tlsConn.Handshake()
	if tlsErr != nil {
		return nil, tlsErr
	}

	if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		return nil, errors.New("Missing peer certificate")
	}

	pubKey := tlsConn.ConnectionState().PeerCertificates[0].PublicKey

	return pubKey, nil
}
