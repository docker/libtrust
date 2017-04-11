package graph

import (
	"testing"
)

func TestSQLGraphSetGetDelete(t *testing.T) {
	testGraphSetGetDelete(SQLFactory{}, t)
}
