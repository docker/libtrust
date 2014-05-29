package libtrust

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"sync"
	"testing"
)

func checkPublicKeyEquals(t *testing.T, actual, expected interface{}) {
	actualPublicKey := actual.(*rsa.PublicKey)
	expectedPublicKey := expected.(*rsa.PublicKey)
	if actualPublicKey.N.Cmp(expectedPublicKey.N) != 0 {
		t.Errorf("Public key values do not match")
	}
	if actualPublicKey.E != expectedPublicKey.E {
		t.Errorf("Public key exponents do not match: expected %d, actual %d", expectedPublicKey.E, actualPublicKey.E)
	}
}

func TestDial(t *testing.T) {
	errorChan := make(chan error)
	connChan := make(chan *tls.Conn)
	var wg sync.WaitGroup
	server := "localhost:6443"
	startErr := startServer(server, connChan, errorChan, &wg)
	if startErr != nil {
		t.Fatalf("Error starting server: %s", startErr)
	}

	id, idErr := NewId()
	if idErr != nil {
		t.Fatalf("Error creating id: %s", idErr)
	}

	InsecureTLS = true
	dialer, dialerErr := NewTrustedDialer(id)
	if dialerErr != nil {
		t.Fatalf("Error creating dialer: %s", dialerErr)
	}

	_, connErr := dialer.Dial("tcp", server)
	if connErr != nil {
		t.Fatalf("Error connecting to server: %s", connErr)
	}

	var serverConn *tls.Conn
	select {
	case serverConn = <-connChan:
		break
	case err := <-errorChan:
		t.Fatalf("Server error: %s", err)
	}

	if len(serverConn.ConnectionState().PeerCertificates) != 1 {
		t.Fatalf("Expecting server receive 1 peer cert: has %d", len(serverConn.ConnectionState().PeerCertificates))
	}

	receivedCert := serverConn.ConnectionState().PeerCertificates[0]
	pubKey, _ := id.Keys()
	checkPublicKeyEquals(t, receivedCert.PublicKey, pubKey)

	close(errorChan)
	wg.Wait()
}

func BenchmarkCreateTrustedDialer(b *testing.B) {
	id, idErr := NewId()
	if idErr != nil {
		b.Fatalf("Error creating id: %s", idErr)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, dialerErr := NewTrustedDialer(id)
		if dialerErr != nil {
			b.Fatalf("Error creating dialer: %s", dialerErr)
		}
	}
}

func getCertPool() (*x509.CertPool, error) {
	CertPool := x509.NewCertPool()
	caBytes, readErr := ioutil.ReadFile("./testcerts/ca.pem")
	if readErr != nil {
		return nil, readErr
	}

	if !CertPool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("Could not load PEM for file")
	}
	return CertPool, nil
}

func serverTlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("./testcerts/cert.pem", "./testcerts/key.pem")

	if err != nil {
		return nil, err
	}

	certPool, certPoolErr := getCertPool()
	if certPoolErr != nil {
		return nil, certPoolErr
	}
	config := tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAnyClientCert,
	}
	return &config, nil
}

func startServer(listen string, connChan chan *tls.Conn, errorChan chan error, wg *sync.WaitGroup) error {
	l, lErr := net.Listen("tcp", listen)
	if lErr != nil {
		return lErr
	}

	tlsConfig, tlsErr := serverTlsConfig()
	if tlsErr != nil {
		return tlsErr
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				tlsConn := tls.Server(conn, tlsConfig)
				defer tlsConn.Close()

				if err := tlsConn.Handshake(); err != nil {
					errorChan <- err
					tlsConn.Close()
					return
				}
				connChan <- tlsConn

			}()
		}
	}()

	wg.Add(1)
	go func() {
		<-errorChan
		l.Close()
		wg.Done()
	}()

	return nil
}
