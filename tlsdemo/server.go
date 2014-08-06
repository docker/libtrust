package main

import (
	"crypto/tls"
	"fmt"
	"github.com/docker/libtrust"
	"github.com/docker/libtrust/jwa"
	"html"
	"log"
	"net"
	"net/http"
)

var (
	serverPrivateKey = `{
		"crv": "P-256",
		"d": "xkqo1SzZJuR-qFAVXhhPQUTIU3Ho2Fa-w3gdot8SYqo",
		"kid": "KNJ2:XUL3:E2U7:3J65:4NPM:OR7Q:ABAO:SC7I:ES7R:LVIN:NJEL:ZGH7",
		"kty": "EC",
		"x": "KR5_NDro3hmvfurhdSTJwcpSu7K8jQJgClV7yrZylkg",
		"y": "iUYO0jYTV44IzQSu64yPn9I2P99HbGJvRix0yoWca8w"
	}`
	clientPublicKey = `{
		"crv": "P-256",
		"kid": "K3JX:4IYK:U3QW:ZE4D:BNAL:5D2W:VFXW:T2KA:DJUR:2EAL:R5PR:LWGR",
		"kty": "EC",
		"x": "G0d8ufy7Cxs_CzH8X_C_xXosIoC8W0MB9kH8qxEctjE",
		"y": "9xA0qceWD04gIkXJHNu3rtv9SxV3Gomgwb8exnabnqk"
	}`
)

func requestHandler(w http.ResponseWriter, r *http.Request) {
	clientCert := r.TLS.PeerCertificates[0]
	keyID := clientCert.Subject.CommonName
	log.Printf("Request from keyID: %s\n", keyID)
	fmt.Fprintf(w, "Hello, client! I'm a server! And you are %T: %s.", clientCert.PublicKey, html.EscapeString(keyID))
}

func main() {
	serverKey, err := jwa.UnmarshalPrivateKeyJSON([]byte(serverPrivateKey))
	if err != nil {
		log.Fatal(err)
	}

	clientKey, err := jwa.UnmarshalPublicKeyJSON([]byte(clientPublicKey))
	if err != nil {
		log.Fatal(err)
	}

	selfSignedServerCert, err := libtrust.GenerateSelfSignedServerCert(
		serverKey, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		log.Fatal(err)
	}

	caPool, err := libtrust.GenerateCACertPool(serverKey, []jwa.PublicKey{clientKey})
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{selfSignedServerCert.Raw},
				PrivateKey:  serverKey.CryptoPrivateKey(),
				Leaf:        selfSignedServerCert,
			},
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}

	server := &http.Server{
		Addr:    "localhost:8888",
		Handler: http.HandlerFunc(requestHandler),
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}

	tlsListener := tls.NewListener(listener, tlsConfig)

	server.Serve(tlsListener)
}
