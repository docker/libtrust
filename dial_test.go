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

func init() {
	certPool, certPoolErr := getCertPool()
	if certPoolErr != nil {
		panic(certPoolErr)
	}
	RootCAs = certPool
	InsecureTLS = false
}

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

	dialer, dialerErr := NewTrustedDialer(id)
	if dialerErr != nil {
		t.Fatalf("Error creating dialer: %s", dialerErr)
	}

	c, connErr := dialer.Dial("tcp", server)
	if connErr != nil {
		t.Fatalf("Error connecting to server: %s", connErr)
	}

	if c.Id() != id {
		t.Fatalf("Mismatched identifiers")
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
	closeErr := c.Close()
	if closeErr != nil {
		t.Fatalf("Error closing connection: %s", closeErr)
	}
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

func TestServer(t *testing.T) {
	tlsConfig, tlsErr := serverTlsConfig()
	if tlsErr != nil {
		t.Fatalf("Error creating server tls config: %s", tlsErr)
	}
	server := "localhost:6443"
	ts := NewTrustedServer(tlsConfig)
	listener, listenerErr := ts.Listen("tcp", server)
	if listenerErr != nil {
		t.Fatalf("Error creating listener: %s", listenerErr)
	}

	errorChan := make(chan error)
	connChan := make(chan net.Conn)

	id, clientErr := spawnClient(server, errorChan)
	if clientErr != nil {
		t.Fatalf("Error spawning client: %s", clientErr)
	}

	go func() {
		c, connErr := listener.Accept()
		if connErr != nil {
			t.Logf("Error accepting connection: %s", connErr)
			close(connChan)
		} else {
			connChan <- c
		}

	}()

	var conn net.Conn
	select {
	case c, ok := <-connChan:
		if !ok {
			t.Fatalf("Unable to accept connection")
		}
		conn = c
	case err := <-errorChan:
		t.Fatalf("Error establishing connection: %s", err)
	}

	pubKey, authErr := ts.Authenticate(conn)
	if authErr != nil {
		t.Fatalf("Error authenticating connection: %s", authErr)
	}

	expectedPubKey, _ := id.Keys()
	checkPublicKeyEquals(t, pubKey, expectedPubKey)

	closeErr := listener.Close()
	if closeErr != nil {
		t.Fatalf("Error closing listener: %s", closeErr)
	}
	close(connChan)
	close(errorChan)
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
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
	}
	return &config, nil
}

func startServer(listen string, connChan chan *tls.Conn, errorChan chan error, wg *sync.WaitGroup) error {
	l, lErr := net.Listen("tcp", listen)
	if lErr != nil {
		return lErr
	}

	tlsConfig, tlsErr := serverTlsConfig()
	tlsConfig.ClientAuth = tls.RequireAnyClientCert
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

func spawnClient(server string, errChan chan error) (Id, error) {
	id, idErr := NewId()
	if idErr != nil {
		return nil, idErr
	}

	dialer, dialerErr := NewTrustedDialer(id)
	if dialerErr != nil {
		return nil, dialerErr
	}

	go func() {
		_, dialErr := dialer.Dial("tcp", server)
		if dialErr != nil {
			errChan <- dialErr
		}
	}()

	return id, nil
}
