package graph

import (
	"testing"
)

var (
	memoryNav    = NewMemoryNavigator()
	memoryGrants = createGrants(memoryNav, MemoryFactory{})
)

func TestMemoryGraphEquals(t *testing.T) {
	testGraphEquals(memoryNav, t)
}

func TestMemoryGrantEquals(t *testing.T) {
	testGrantEquals(memoryGrants, t)
}

func TestMemoryNodeReject(t *testing.T) {
	item := memoryNav.NewNode("erikh/is/cool")
	notEqual := memoryNav.NewNode("erikh/is/not/cool")

	var tmp []Node

	graphs := []MemoryNode{
		MemoryNode{children: []Node{item, notEqual}},
		MemoryNode{children: []Node{notEqual, item}},
		MemoryNode{children: []Node{item, notEqual, item}},
		MemoryNode{children: []Node{notEqual, item, notEqual}},
		MemoryNode{children: []Node{notEqual, item, item, notEqual}},
		MemoryNode{children: []Node{item, item, notEqual}},
		MemoryNode{children: []Node{notEqual, item, item}},
	}

	for _, from := range graphs {
		tmp = nodeReject(from.Children(), item)

		if nodeExists(tmp, item) {
			t.Fatal("item still exists in graph")
		}

		if !nodeExists(tmp, notEqual) {
			t.Fatal("removed item from result that should not have been removed")
		}
	}
}

func TestMemoryGrantReject(t *testing.T) {
	for i := 0; i < len(memoryGrants); i++ {
		tmp := grantReject(memoryGrants, memoryGrants[i])

		if grantExists(tmp, memoryGrants[i]) {
			t.Fatal("item still exists in memoryGrants list")
		}

		for x := 0; x < len(memoryGrants); x++ {
			if x == i {
				continue
			}

			if !grantExists(tmp, memoryGrants[x]) {
				t.Fatal("item should exist in memoryGrants list but does not")
			}
		}
	}
}

func TestMemoryGraphName(t *testing.T) {
	testGraphName(memoryNav, t)
}

func TestMemoryGraphSetParent(t *testing.T) {
	testGraphSetParent(memoryNav, t)
}

func TestMemoryGraphAddRemoveChild(t *testing.T) {
	testGraphAddRemoveChild(memoryNav, t)
}

func TestMemoryGraphAddRemoveGrant(t *testing.T) {
	testAddRemoveGrant(memoryNav, memoryGrants, t)
}

func TestMemoryGraphIsDelegated(t *testing.T) {
	testGraphIsDelegated(memoryNav, MemoryFactory{}, t)
}

func TestMemoryGraphIsCapable(t *testing.T) {
	testGraphIsCapable(memoryNav, MemoryFactory{}, t)
}
