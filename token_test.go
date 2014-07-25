package libtrust

import (
	"bufio"
	"bytes"
	"os"
	"testing"
	"time"
)

var (
	rsaIDs   []*RsaID
	ecdsaIDs []*EcdsaID
)

func init() {
	f, err := os.Open("test_rsa_keys")
	if err != nil {
		panic(err)
	}

	rsaIDs = make([]*RsaID, 0, 5)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		id, err := ImportRsaID(scanner.Text())
		if err != nil {
			panic(err)
		}
		rsaIDs = append(rsaIDs, id)
	}
	if len(rsaIDs) < 5 {
		panic("Could not read needed expected keys")
	}

	f, err = os.Open("test_ecdsa_keys")
	if err != nil {
		panic(err)
	}

	ecdsaIDs = make([]*EcdsaID, 0, 5)
	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		id, err := ImportEcdsaID(scanner.Text())
		if err != nil {
			panic(err)
		}
		ecdsaIDs = append(ecdsaIDs, id)
	}
	if len(ecdsaIDs) < 5 {
		panic("Could not read needed expected keys")
	}
}

func TestClaimSigning(t *testing.T) {
	claim := Claim{
		Subject: "/dockertest/unitest",
		Action:  "run",
	}
	t1, err := claim.Sign(rsaIDs[0])
	if err != nil {
		t.Fatalf("Error signing claim: %s", err)
	}

	t2, err := ParseToken(t1.String())
	if err != nil {
		t.Fatalf("Error parsing t2: %s", err)
	}

	if bytes.Compare(t1.compact, t2.compact) != 0 {
		t.Fatalf("Mismatched compact values:\n\tExpected: %s\n\tActual: %s", string(t1.compact), string(t2.compact))
	}

	if bytes.Compare(rsaIDs[0].public.N.Bytes(), t2.issuer.(*RsaID).public.N.Bytes()) != 0 {
		t.Fatalf("Mismatched public key (N):\n\tExpected: %s\n\tActual: %s", rsaIDs[0].public.N.String(), t2.issuer.(*RsaID).public.N.String())
	}
}

func TestClaimECSigning(t *testing.T) {
	claim := Claim{
		Subject: "/dockertest/unitest",
		Action:  "run",
	}
	t1, err := claim.Sign(ecdsaIDs[0])
	if err != nil {
		t.Fatalf("Error signing claim: %s", err)
	}

	t2, err := ParseToken(t1.String())
	if err != nil {
		t.Fatalf("Error parsing t2: %s", err)
	}

	if bytes.Compare(t1.compact, t2.compact) != 0 {
		t.Fatalf("Mismatched compact values:\n\tExpected: %s\n\tActual: %s", string(t1.compact), string(t2.compact))
	}

	if bytes.Compare(ecdsaIDs[0].public.X.Bytes(), t2.issuer.(*EcdsaID).public.X.Bytes()) != 0 {
		t.Fatalf("Mismatched public key (X):\n\tExpected: %s\n\tActual: %s", ecdsaIDs[0].public.X.String(), t2.issuer.(*EcdsaID).public.X.String())
	}

	if bytes.Compare(ecdsaIDs[0].public.Y.Bytes(), t2.issuer.(*EcdsaID).public.Y.Bytes()) != 0 {
		t.Fatalf("Mismatched public key (Y):\n\tExpected: %s\n\tActual: %s", ecdsaIDs[0].public.Y.String(), t2.issuer.(*EcdsaID).public.Y.String())
	}
}

func TestSigningTokens(t *testing.T) {
	claim := Claim{
		Subject: "/dockertest/unitest",
		Action:  "run",
	}
	t1, err := claim.Sign(rsaIDs[1])
	if err != nil {
		t.Fatalf("Error signing claim: %s", err)
	}

	t1Signed, err := t1.Sign(rsaIDs[2])
	if err != nil {
		t.Fatalf("Error signing token: %s", err)
	}

	t2, err := ParseToken(t1Signed.String())
	if err != nil {
		t.Fatalf("Error parsing t2: %s", err)
	}

	if bytes.Compare(t1Signed.compact, t2.compact) != 0 {
		t.Fatalf("Mismatched compact values:\n\tExpected: %s\n\tActual: %s", string(t1.compact), string(t2.compact))
	}

	if bytes.Compare(rsaIDs[1].public.N.Bytes(), t2.issuer.(*RsaID).public.N.Bytes()) != 0 {
		t.Fatalf("Mismatched public key (N):\n\tExpected: %s\n\tActual: %s", rsaIDs[1].public.N.String(), t2.issuer.(*RsaID).public.N.String())
	}

	if bytes.Compare(rsaIDs[2].public.N.Bytes(), t2.verifier.(*RsaID).public.N.Bytes()) != 0 {
		t.Fatalf("Mismatched public key (N):\n\tExpected: %s\n\tActual: %s", rsaIDs[2].public.N.String(), t2.verifier.(*RsaID).public.N.String())
	}

}

func BenchmarkClaimRsaParsing(b *testing.B) {
	claim := Claim{
		Subject: "/dockertest/unitest",
		Action:  "run",
	}
	t1, err := claim.Sign(rsaIDs[3])
	if err != nil {
		b.Fatalf("Error signing claim: %s", err)
	}

	tokenString := t1.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t2, err := ParseToken(tokenString)
		b.StopTimer()
		if err != nil {
			b.Fatalf("Error parsing t2: %s", err)
		}

		if bytes.Compare(t1.compact, t2.compact) != 0 {
			b.Fatalf("Mismatched compact values:\n\tExpected: %s\n\tActual: %s", string(t1.compact), string(t2.compact))
		}
		b.StartTimer()
	}
}

func BenchmarkClaimEcdsaParsing(b *testing.B) {
	claim := Claim{
		Subject: "/dockertest/unitest",
		Action:  "run",
	}
	t1, err := claim.Sign(ecdsaIDs[3])
	if err != nil {
		b.Fatalf("Error signing claim: %s", err)
	}

	tokenString := t1.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t2, err := ParseToken(tokenString)
		b.StopTimer()
		if err != nil {
			b.Fatalf("Error parsing t2: %s", err)
		}

		if bytes.Compare(t1.compact, t2.compact) != 0 {
			b.Fatalf("Mismatched compact values:\n\tExpected: %s\n\tActual: %s", string(t1.compact), string(t2.compact))
		}
		b.StartTimer()
	}
}

func BenchmarkClaimRsaSigning(b *testing.B) {
	claim := Claim{
		Subject:    "/dockertest/unitest",
		Action:     "run",
		Expiration: time.Now().Add(time.Minute),
	}
	for i := 0; i < b.N; i++ {
		_, err := claim.Sign(rsaIDs[3])
		if err != nil {
			b.Fatalf("Error signing claim: %s", err)
		}

	}
}

func BenchmarkClaimEcdsaSigning(b *testing.B) {
	claim := Claim{
		Subject:    "/dockertest/unitest",
		Action:     "run",
		Expiration: time.Now().Add(time.Minute),
	}
	for i := 0; i < b.N; i++ {
		_, err := claim.Sign(ecdsaIDs[3])
		if err != nil {
			b.Fatalf("Error signing claim: %s", err)
		}

	}
}
