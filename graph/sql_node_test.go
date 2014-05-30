package graph

import (
	"testing"
)

func TestSQLGraphEquals(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	testGraphEquals(sqlNav, t)
}

func TestSQLGrantEquals(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	sqlGrants := createGrants(sqlNav, SQLFactory{})
	testGrantEquals(sqlGrants, t)
}

func TestSQLGraphName(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	testGraphName(sqlNav, t)
}

func TestSQLGraphSetParent(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	testGraphSetParent(sqlNav, t)
}

func TestSQLGraphAddRemoveChild(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	testGraphAddRemoveChild(sqlNav, t)
}

func TestSQLGraphAddRemoveGrant(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	sqlGrants := createGrants(sqlNav, SQLFactory{})
	testAddRemoveGrant(sqlNav, sqlGrants, t)
}

func TestSQLGraphIsDelegated(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	testGraphIsDelegated(sqlNav, SQLFactory{}, t)
}

func TestSQLGraphIsCapable(t *testing.T) {
	sqlNav := SQLFactory{}.NewNavigator()
	testGraphIsCapable(sqlNav, SQLFactory{}, t)
}
