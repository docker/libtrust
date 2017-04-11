package graph

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

type Factory interface {
	NewNavigator() GraphNavigator
	NewGrant(map[string]interface{}) Grant
}

type MemoryFactory struct{}

func (m MemoryFactory) NewNavigator() GraphNavigator {
	return NewMemoryNavigator()
}

func (m MemoryFactory) NewGrant(msi map[string]interface{}) Grant {
	return MemoryGrant{
		category: msi["category"].(Category),
		action:   msi["action"].(Action),
		node:     msi["node"].(Node),
	}
}

type SQLFactory struct{}

func (s SQLFactory) createSchema(db *sql.DB) error {
	f, err := os.Open("schema.sql")
	if err != nil {
		return err
	}

	defer f.Close()

	content, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	queries := strings.Split(string(content), "\n--\n")

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s SQLFactory) NewNavigator() GraphNavigator {
	os.Remove("/tmp/libtrust.db")

	db, err := sql.Open("sqlite3", "/tmp/libtrust.db")
	if err != nil {
		panic(err)
	}

	err = s.createSchema(db)
	if err != nil {
		panic(err)
	}

	return NewSQLNavigator(db)
}

func (s SQLFactory) NewGrant(msi map[string]interface{}) Grant {
	g := &SQLGrant{
		action:   msi["action"].(Action),
		category: msi["category"].(Category),
		node:     msi["node"].(Node),
		parent:   nil,
		nav:      msi["navigator"].(*SQLNavigator),
	}

	err := g.Commit()

	if err != nil {
		panic(err)
	}

	return g
}

func createGrants(nav GraphNavigator, f Factory) []Grant {
	return []Grant{
		f.NewGrant(map[string]interface{}{
			"category":  Authorize,
			"action":    LS,
			"node":      nav.NewNode("one"),
			"navigator": nav,
		}),
		f.NewGrant(map[string]interface{}{
			"category":  Delegate,
			"action":    LS,
			"node":      nav.NewNode("two"),
			"navigator": nav,
		}),
		f.NewGrant(map[string]interface{}{
			"category":  Authorize,
			"action":    CD,
			"node":      nav.NewNode("three"),
			"navigator": nav,
		}),
		f.NewGrant(map[string]interface{}{
			"category":  Delegate,
			"action":    CD,
			"node":      nav.NewNode("four"),
			"navigator": nav,
		}),
	}
}

func grantExists(gList []Grant, item Grant) bool {
	for _, this := range gList {
		if this.Equals(item) {
			return true
		}
	}

	return false
}

func nodeExists(gList []Node, item Node) bool {
	for _, thisNode := range gList {
		if thisNode.Equals(item) {
			return true
		}
	}

	return false
}

func testGraphEquals(gn GraphNavigator, t *testing.T) {
	if gn.NewNode("one").Equals(gn.NewNode("two")) {
		t.Fatal("one equals two")
	}

	if !gn.NewNode("one").Equals(gn.NewNode("one")) {
		t.Fatal("one does not equal one")
	}
}

func testGrantEquals(grants []Grant, t *testing.T) {
	for i := 1; i < len(grants); i += 2 {
		if grants[i-1].Equals(grants[i]) {
			t.Fatal("Grants are equal when they should not be")
		}
	}

	for _, grant := range grants {
		if !grant.Equals(grant) {
			t.Fatal("Grants are not equal when they should be")
		}
	}
}

func testGraphName(gn GraphNavigator, t *testing.T) {
	if gn.NewNode("one").Name() != "one" || gn.NewNode("two").Name() == "one" {
		t.Fatal("did not yield the proper name")
	}
}

func testGraphSetParent(gn GraphNavigator, t *testing.T) {
	node := gn.NewNode("one")
	parent1 := gn.NewNode("parent1")
	parent2 := gn.NewNode("parent2")

	node.SetParent(parent1)

	if !parent1.Equals(node.Parent()) {
		t.Fatal("Could not set initial parent")
	}

	if !nodeExists(parent1.Children(), node) {
		t.Fatal("node is not a child of parent")
	}

	node.SetParent(parent2)

	if !parent2.Equals(node.Parent()) {
		t.Fatal("Parent was not changed on request")
	}

	if !nodeExists(parent2.Children(), node) {
		t.Fatal("node is not a child of the new parent")
	}

	if nodeExists(parent1.Children(), node) {
		t.Fatal("node still exists in original parent")
	}
}

func testGraphAddRemoveChild(gn GraphNavigator, t *testing.T) {
	root := gn.NewNode("one")
	child1 := gn.NewNode("two")
	child2 := gn.NewNode("three")

	root.AddChild(child1)
	root.AddChild(child2)

	if !nodeExists(root.Children(), child1) || !nodeExists(root.Children(), child2) {
		t.Fatal("Children did not get added to root")
	}

	root.RemoveChild(child1)

	if nodeExists(root.Children(), child1) {
		t.Fatal("Removed child did not get removed from root")
	}

	root.RemoveChild(child2)

	if nodeExists(root.Children(), child2) {
		t.Fatal("Removed child did not get removed from root")
	}
}

func testAddRemoveGrant(gn GraphNavigator, grants []Grant, t *testing.T) {
	one := gn.NewNode("one")

	one.AddGrant(grants[0])

	if !grantExists(one.Grants(), grants[0]) {
		t.Fatal("single addgrant failed")
	}

	for _, grant := range grants {
		one.AddGrant(grant)
	}

	for _, grant := range grants {
		if !grantExists(one.Grants(), grant) {
			t.Fatal("mass addgrant failed")
		}
	}

	err := one.RemoveGrant(grants[0])
	if err != nil {
		t.Fatal(err)
	}

	if grantExists(one.Grants(), grants[0]) {
		t.Fatal("single removegrant failed")
	}

	for _, grant := range one.Grants() {
		one.RemoveGrant(grant)
	}

	//if _, ok := gn.(*SQLNavigator); ok {
	//panic("hi")
	//}

	for _, grant := range grants {
		if grantExists(one.Grants(), grant) {
			t.Fatal("mass removegrant failed")
		}
	}
}

func testGraphIsDelegated(gn GraphNavigator, f Factory, t *testing.T) {
	user1 := gn.NewNode("user1")
	user2 := gn.NewNode("user2")

	grant := f.NewGrant(map[string]interface{}{
		"category":  Delegate,
		"action":    LS,
		"node":      user2,
		"navigator": gn,
	})

	user1.AddGrant(grant)
	user2.SetParent(user1)

	if !user2.IsDelegated(LS) {
		t.Fatal("user2 is not delegated when it should be")
	}

	if user1.IsDelegated(LS) {
		t.Fatal("user1 is delegated when it should not be")
	}

	user1.RemoveGrant(grant)

	if user2.IsDelegated(LS) {
		t.Fatal("user2 is still delegated after revocation")
	}
}

func testGraphIsCapable(gn GraphNavigator, f Factory, t *testing.T) {
	user1 := gn.NewNode("user1")
	user2 := gn.NewNode("user2")
	user3 := gn.NewNode("user3")

	grant := f.NewGrant(map[string]interface{}{
		"category":  Delegate,
		"action":    LS,
		"node":      user2,
		"navigator": gn,
	})

	grant2 := f.NewGrant(map[string]interface{}{
		"category":  Authorize,
		"action":    LS,
		"node":      user3,
		"navigator": gn,
	})

	user1.AddGrant(grant)
	user2.SetParent(user1)
	user2.AddGrant(grant2)
	user3.SetParent(user2)

	if !user3.IsCapable(LS) {
		t.Fatal("user3 is not capable of executing LS")
	}

	if user2.IsCapable(LS) {
		t.Fatal("user2 is unintentionally both delegated and authorized to execute LS")
	}
}

func testGraphSetGetDelete(f Factory, t *testing.T) {
	root := f.NewNavigator()
	one := root.NewNode("one")

	root.Set(one)

	one_tmp, err := root.Get("one")

	if err != nil {
		t.Fatal(err)
	}

	if !one_tmp.Equals(one) {
		t.Fatal("Found object was not equal to set object")
	}

	node, _ := root.Get("two")

	if node != nil {
		t.Fatal("Found a node that should not exist")
	}

	two := root.NewNode("two")

	root.Set(two)

	node, err = root.Get("two")
	if err != nil {
		t.Fatal(err)
	}

	if !node.Equals(two) {
		t.Fatal("Found object was not equal to set object")
	}

	node, err = root.Get("two")
	if err != nil {
		t.Fatal(err)
	}

	if node.Equals(one_tmp) {
		t.Fatal("retrieved two equal objects that should not be equal")
	}

	root.Delete("one")

	node, _ = root.Get("one")

	if node != nil {
		t.Fatal("Successfully retrieved an node that should not exist")
	}

	node, err = root.Get("two")
	if err != nil {
		t.Fatal(err)
	}

	if node.Equals(one_tmp) {
		t.Fatal("retrieved two equal objects that should not be equal")
	}
}

func testGraphWalk(f Factory, t *testing.T) {
	m := f.NewNavigator()

	var s string
	sp := &s

	//
	// one
	//  -> two
	//      -> three
	//  -> four
	//      -> five
	//

	one := m.NewNode("one")
	two := m.NewNode("two")
	three := m.NewNode("three")
	four := m.NewNode("four")
	five := m.NewNode("five")

	one.AddChild(two)
	one.AddChild(four)

	two.AddChild(three)

	four.AddChild(five)

	ok, err := Walk(one, func(n Node) (bool, error) {
		*sp = *sp + n.Name()
		return true, nil
	})

	if !ok || err != nil {
		t.Fatal("Encountered an error while walking the node tree")
	}

	if *sp != "twothreefourfive" {
		t.Fatal(fmt.Sprintf("Expected result in string buffer (%s) does not match `twothreefourfive`", *sp))
	}

	*sp = ""

	ok, err = Walk(one, func(n Node) (bool, error) {
		*sp = *sp + n.Name()
		return false, nil
	})

	if ok || err != nil {
		t.Fatal("Unexpected error or ok on deliberately failing Walk")
	}

	if *sp != "two" {
		t.Fatal(fmt.Sprintf("Expected result in string buffer (%s) does not match `two`", *sp))
	}

	*sp = ""

	ok, err = Walk(one, func(n Node) (bool, error) {
		*sp = *sp + n.Name()
		return true, errors.New("robot parade")
	})

	if !ok || err == nil {
		t.Fatal("Unexpected error or ok on deliberately failing Walk")
	}

	if *sp != "two" {
		t.Fatal(fmt.Sprintf("Expected result in string buffer (%s) does not match `two`", *sp))
	}

	*sp = ""

	ok, err = Walk(one, func(n Node) (bool, error) {
		*sp = *sp + n.Name()

		if n.Name() == "four" {
			return false, nil
		} else {
			return true, nil
		}
	})

	if ok || err != nil {
		t.Fatal("Unexpected error or ok on deliberately failing Walk")
	}

	if *sp != "twothreefour" {
		t.Fatal(fmt.Sprintf("Expected result in string buffer (%s) does not match `twothree`", *sp))
	}
}
