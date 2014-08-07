package main

import (
	"crypto/tls"
	"github.com/docker/libtrust"
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

	selfSignedClientCert, err := libtrust.GenerateSelfSignedClientCert(clientKey)
	if err != nil {
		log.Fatal(err)
	}

	caPool, err := libtrust.GenerateCACertPool(clientKey, []jwa.PublicKey{serverKey})
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					tls.Certificate{
						Certificate: [][]byte{selfSignedClientCert.Raw},
						PrivateKey:  clientKey.CryptoPrivateKey(),
						Leaf:        selfSignedClientCert,
					},
				},
				RootCAs: caPool,
			},
		},
	}

	var makeRequest = func(url string) {
		resp, err := client.Get(url)
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
	}

	makeRequest("https://localhost:8888")
	makeRequest("https://127.0.0.1:8888")
}
