package trustchain

import (
	"crypto/rand"
	"testing"
	"time"
)

func generateKey() KeyID {
	var k KeyID
	n, err := rand.Read(k[:])
	if err != nil {
		panic(err)
	}
	if n != 32 {
		panic("Could not create key")
	}
	return k
}

func TestChainVerification(t *testing.T) {
	authority := newKeyAuthority()
	root := generateKey()
	authority.Authorities[string(root[:])] = "/"

	intermediate1 := generateKey()
	intermediate2 := generateKey()

	chain := make(Chain, 2)
	chain[0] = &Link{
		Granter:    intermediate2,
		Grantee:    intermediate1,
		Namespace:  "/subspace/name",
		Expiration: time.Now().Add(time.Minute),
	}
	chain[1] = &Link{
		Granter:    intermediate1,
		Grantee:    root,
		Namespace:  "/subspace/",
		Expiration: time.Now().Add(time.Minute),
	}

	err := authority.VerifyChain(chain)
	if err != nil {
		t.Fatalf("Error verifying chain: %s", err)
	}

	// Not verified
	chain[1] = &Link{
		Granter:    intermediate1,
		Grantee:    generateKey(),
		Namespace:  "/subspace/",
		Expiration: time.Now().Add(time.Minute),
	}
	err = authority.VerifyChain(chain)
	if err == nil {
		t.Fatalf("Chain incorrectly verified")
	}
	if err != ErrRootUnverified {
		t.Fatalf("Unexpected error verifying chain: %s", err)
	}

	authority.Authorities[string(root[:])] = "/subspace_other/"

	chain[1] = &Link{
		Granter:    intermediate1,
		Grantee:    root,
		Namespace:  "/subspace/",
		Expiration: time.Now().Add(time.Minute),
	}
	err = authority.VerifyChain(chain)
	if err == nil {
		t.Fatalf("Chain incorrectly verified")
	}
	if err != ErrRootUnverified {
		t.Fatalf("Unexpected error verifying chain: %s", err)
	}
}

func TestInvalidChain(t *testing.T) {
	authority := newKeyAuthority()

	intermediate1 := generateKey()
	intermediate2 := generateKey()

	chain := make(Chain, 2)
	chain[0] = &Link{
		Granter:    intermediate2,
		Grantee:    intermediate1,
		Namespace:  "/subspace_other/name",
		Expiration: time.Now().Add(time.Minute),
	}

	chain[1] = &Link{
		Granter:    intermediate1,
		Grantee:    generateKey(),
		Namespace:  "/subspace/",
		Expiration: time.Now().Add(time.Minute),
	}

	err := authority.VerifyChain(chain)
	if err == nil {
		t.Fatalf("Chain incorrectly verified")
	}
	if err != ErrInvalidChain {
		t.Fatalf("Unexpected error verifying chain: %s", err)
	}

	chain[0] = &Link{
		Granter:    intermediate2,
		Grantee:    generateKey(),
		Namespace:  "/subspace/name",
		Expiration: time.Now().Add(time.Minute),
	}

	err = authority.VerifyChain(chain)
	if err == nil {
		t.Fatalf("Chain incorrectly verified")
	}
	if err != ErrInvalidChain {
		t.Fatalf("Unexpected error verifying chain: %s", err)
	}

	chain[0] = &Link{
		Granter:    intermediate2,
		Grantee:    intermediate1,
		Namespace:  "/subspace/name",
		Expiration: time.Now().Add(-2 * time.Minute),
	}

	err = authority.VerifyChain(chain)
	if err == nil {
		t.Fatalf("Chain incorrectly verified")
	}
	if err != ErrInvalidChain {
		t.Fatalf("Unexpected error verifying chain: %s", err)
	}
}
