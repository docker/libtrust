package graph

import (
	"testing"
)

func TestMemoryGraphWalk(t *testing.T) {
	testGraphWalk(MemoryFactory{}, t)
}
