package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/docker/libtrust/jwa"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	clientPrivateKey = `{
		"crv": "P-256",
		"d": "aaK8tX-bxv6tj8ojkJmGswiFD2EQO_cMYeW852botKU",
		"kid": "K3JX:4IYK:U3QW:ZE4D:BNAL:5D2W:VFXW:T2KA:DJUR:2EAL:R5PR:LWGR",
		"kty": "EC",
		"x": "G0d8ufy7Cxs_CzH8X_C_xXosIoC8W0MB9kH8qxEctjE",
		"y": "9xA0qceWD04gIkXJHNu3rtv9SxV3Gomgwb8exnabnqk"
	}`
	serverPublicKey = `{
		"crv": "P-256",
		"kid": "KNJ2:XUL3:E2U7:3J65:4NPM:OR7Q:ABAO:SC7I:ES7R:LVIN:NJEL:ZGH7",
		"kty": "EC",
		"x": "KR5_NDro3hmvfurhdSTJwcpSu7K8jQJgClV7yrZylkg",
		"y": "iUYO0jYTV44IzQSu64yPn9I2P99HbGJvRix0yoWca8w"
	}`
)

func main() {
	clientKey, err := jwa.UnmarshalPrivateKeyJSON([]byte(clientPrivateKey))
	if err != nil {
		log.Fatal(err)
	}

	serverKey, err := jwa.UnmarshalPublicKeyJSON([]byte(serverPublicKey))
	if err != nil {
		log.Fatal(err)
	}

	selfSignedCertPEM, err := clientKey.GeneratePEMCert(clientKey.PublicKey(), nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	selfSignedCertDER, _ := pem.Decode(selfSignedCertPEM)
	if selfSignedCertDER == nil {
		log.Fatal("unable to decode self-signed certificate PEM data")
	}

	signedServerCertPEM, err := clientKey.GeneratePEMCert(serverKey, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{selfSignedCertDER.Bytes},
		PrivateKey:  clientKey.CryptoPrivateKey(),
	}

	serverCAs := x509.NewCertPool()
	if !serverCAs.AppendCertsFromPEM(signedServerCertPEM) {
		log.Fatalln("unable to add server CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            serverCAs,
		InsecureSkipVerify: false,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://localhost:8888")
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(resp.Status)
	log.Println(string(body))

	resp, err = client.Get("https://127.0.0.1:8888")
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(resp.Status)
	log.Println(string(body))
}
