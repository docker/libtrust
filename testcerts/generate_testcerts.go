package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const RSABITS = 2048

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, RSABITS)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return
	}

	notBefore := time.Date(2013, 12, 31, 23, 59, 59, 0, time.UTC)
	notAfter := time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			Organization: []string{"libtrust"},
		},
		NotBefore:  notBefore,
		NotAfter:   notAfter,
		MaxPathLen: 255,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	caTemplate := template
	caTemplate.IsCA = true
	caTemplate.KeyUsage |= x509.KeyUsageCertSign

	caBytes, caBytesErr := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if caBytesErr != nil {
		log.Fatalf("Error creating ca certificate: %s", caBytesErr)
		return
	}
	parent, parentErr := x509.ParseCertificate(caBytes)
	if parentErr != nil {
		log.Fatalf("Error parsing parent certificate: %s", parentErr)
		return
	}

	certBytes, certBytesErr := x509.CreateCertificate(rand.Reader, &template, parent, &priv.PublicKey, priv)
	if certBytesErr != nil {
		log.Fatalf("Error creating certificate: %s", certBytesErr)
		return
	}

	caOut, err := os.Create("ca.pem")
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
		return
	}
	pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	pem.Encode(caOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	caOut.Close()
	log.Print("written ca.pem\n")

	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
		return
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()
	log.Print("written cert.pem\n")

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written key.pem\n")
}
