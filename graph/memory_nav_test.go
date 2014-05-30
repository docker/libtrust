package graph

import (
	"testing"
)

func TestMemoryGraphSetGetDelete(t *testing.T) {
	testGraphSetGetDelete(MemoryFactory{}, t)
}
