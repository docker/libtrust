package libtrust

import (
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
)

const (
	key1 = "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"
	key2 = "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"
)

var (
	id1 *RsaId
	id2 *RsaId
)

func init() {
	fmt.Fprintf(os.Stderr, "Loading test keys...\n")
	i1, err := ImportId(key1)
	if err != nil {
		panic(err)
	}
	i2, err := ImportId(key2)
	if err != nil {
		panic(err)
	}
	id1 = i1
	id2 = i2
}

func EqualPrivateKeys(k1, k2 *rsa.PrivateKey) bool {
	if k1.PublicKey.N.Cmp(k2.PublicKey.N) != 0 {
		return false
	}
	if k1.PublicKey.E != k2.PublicKey.E {
		return false
	}
	if k1.D.Cmp(k2.D) != 0 {
		return false
	}
	if len(k1.Primes) != len(k2.Primes) {
		return false
	}
	for i := range k1.Primes {
		if k1.Primes[i].Cmp(k2.Primes[i]) != 0 {
			return false
		}
	}
	if k1.Precomputed.Dp.Cmp(k2.Precomputed.Dp) != 0 {
		return false
	}
	if k1.Precomputed.Dq.Cmp(k2.Precomputed.Dq) != 0 {
		return false
	}
	if k1.Precomputed.Qinv.Cmp(k2.Precomputed.Qinv) != 0 {
		return false
	}
	if len(k1.Precomputed.CRTValues) != len(k2.Precomputed.CRTValues) {
		return false
	}
	for i := range k1.Precomputed.CRTValues {
		if k1.Precomputed.CRTValues[i].Exp.Cmp(k2.Precomputed.CRTValues[i].Exp) != 0 {
			return false
		}
		if k1.Precomputed.CRTValues[i].Coeff.Cmp(k2.Precomputed.CRTValues[i].Coeff) != 0 {
			return false
		}
		if k1.Precomputed.CRTValues[i].R.Cmp(k2.Precomputed.CRTValues[i].R) != 0 {
			return false
		}
	}
	return true
}

func TestExportImport(t *testing.T) {
	data1 := id1.Export()
	if data1 != key1 {
		t.Fatalf("%#v", data1)
	}
	data2 := id2.Export()
	if data2 != key2 {
		t.Fatalf("%#v", data2)
	}

	imported1, err := ImportId(data1)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualPrivateKeys(id1.k, imported1.k) {
		t.Fatalf("Keys for id1 do not match")
	}

	imported2, err := ImportId(data2)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualPrivateKeys(id2.k, imported2.k) {
		t.Fatalf("Keys for id2 do not match")
	}
}
