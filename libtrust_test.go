package libtrust

import (
	"fmt"
	"os"
	"testing"
)

var (
	id1 *RsaId
	id2 *RsaId
)

func init() {
	fmt.Fprintf(os.Stderr, "Generating test keys...\n")
	i1, err := NewId()
	if err != nil {
		panic(err)
	}
	i2, err := NewId()
	if err != nil {
		panic(err)
	}
	id1 = i1
	id2 = i2
}

func TestNewRandom(t *testing.T) {
	if id1.String() == id2.String() {
		t.Fatalf("identical keys: %s = %s", id1.String(), id2.String())
	}
}

func TestExportImport(t *testing.T) {
	id1, err := NewId()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := NewId()
	if err != nil {
		t.Fatal(err)
	}
	data1 := id1.Export()
	if data1 == nil {
		t.Fatalf("%#v", data1)
	}
	data2 := id2.Export()
	if data2 == nil {
		t.Fatalf("%#v", data2)
	}
	if string(data1) == string(data2) {
		t.Fatalf("%s", data1)
	}
	_, err = ImportId(data1)
	if err != nil {
		t.Fatal(err)
	}
	// FIXME: check that id and id1 are the same key
}
