package libtrust

import (
	"testing"
)

var (
	// Re-use shared keys across tests, because generating keys takes a long time...
	shared1 Id
	shared2 Id
)

// THIS TEST MUST BE RUN FIRST
// (because it sets `shared1` and `shared2`)
func TestNewRandom(t *testing.T) {
	id1, err := NewId()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := NewId()
	if err != nil {
		t.Fatal(err)
	}
	if id1.String() == id2.String() {
		t.Fatalf("identical keys: %s = %s", id1.String(), id2.String())
	}
	// Re-use in other tests
	shared1 = id1
	shared2 = id2
}
