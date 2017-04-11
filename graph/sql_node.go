package graph

import (
	"errors"
)

type SQLNode struct {
	nav *SQLNavigator
	id  string
}

func (sn *SQLNode) Commit() error {
	if node, err := sn.nav.Get(sn.id); node == nil {
		if err != nil {
			return err
		}

		_, err = sn.nav.execute("insert into nodes (name) values (?)", sn.id)
		if err != nil {
			return err
		}
	}

	Walk(sn, func(n Node) (bool, error) {
		if err := n.(*SQLNode).Commit(); err != nil {
			return false, err
		} else {
			return true, nil
		}
	})

	return nil
}

func (sn *SQLNode) Name() string {
	return sn.id
}

func (sn *SQLNode) AddChild(n Node) error {
	if err := sn.Commit(); err != nil {
		return err
	}

	if err := n.(*SQLNode).Commit(); err != nil {
		return err
	}

	if _, err := sn.nav.execute("update node_parents set parent_name=? where name=?", sn.id, n.(*SQLNode).id); err != nil {
		return err
	}

	return nil
}

func (sn *SQLNode) RemoveChild(n Node) error {
	if _, err := sn.nav.execute("delete from node_parents where parent_name=? and name=?", sn.id, n.(*SQLNode).id); err != nil {
		return err
	}

	return nil
}

func (sn *SQLNode) Children() []Node {
	nodes := make([]Node, 0)

	rows, err := sn.nav.db.Query("select name from node_parents where parent_name=?", sn.id)
	if err != nil {
		return nil
	}

	for rows.Next() {
		var name string

		err := rows.Scan(&name)
		if err != nil {
			return nil
		}

		node, err := sn.nav.Get(name)
		if err != nil {
			return nil
		}

		nodes = append(nodes, node.(*SQLNode))
	}

	return nodes
}

func (sn *SQLNode) NewGrant(c Category, a Action, n Node) (Grant, error) {
	grant := &SQLGrant{
		node:     n,
		action:   a,
		category: c,
		parent:   sn,
		nav:      sn.nav,
	}

	return grant, sn.AddGrant(grant)
}

func (sn *SQLNode) AddGrant(g Grant) error {
	if g == nil || (g.(*SQLGrant).parent != nil && g.(*SQLGrant).parent.Name() != sn.Name()) {
		return errors.New("Invalid grant -- must have either no parent or receiver must be the parent")
	}
	g.(*SQLGrant).parent = sn
	return g.(*SQLGrant).Commit()
}

func (sn *SQLNode) RemoveGrant(g Grant) error {
	if g == nil || (g.(*SQLGrant).parent != nil && g.(*SQLGrant).parent.Name() != sn.Name()) {
		return errors.New("Invalid grant -- must have either no parent or receiver must be the parent")
	}

	g.(*SQLGrant).parent = sn
	return g.(*SQLGrant).Delete()
}

func (sn *SQLNode) Grants() []Grant {
	grants := make([]Grant, 0)

	rows, err := sn.nav.db.Query("select id, category, action, node from grants where parent=?", sn.id)
	if err != nil {
		return nil
	}

	for rows.Next() {
		var to_node string
		var id, action, category uint

		if err := rows.Scan(&id, &category, &action, &to_node); err != nil {
			return nil
		}
		node, err := sn.nav.Get(to_node)
		if err != nil {
			return nil
		}

		grants = append(grants, &SQLGrant{id: id, nav: sn.nav, parent: sn, node: node, action: Action(action), category: Category(category)})
	}

	return grants
}

func (sn *SQLNode) SetParent(n Node) error {
	return n.AddChild(sn)
}

func (sn *SQLNode) Parent() Node {
	row := sn.nav.db.QueryRow("select parent_name from node_parents where name=?", sn.id)

	var parent_name string

	if err := row.Scan(&parent_name); err != nil {
		return nil
	}

	node, err := sn.nav.Get(parent_name)
	if err != nil {
		return nil
	}

	return node
}

func (sn *SQLNode) IsCapable(act Action) bool {
	parent := sn.Parent().(*SQLNode)

	if !parent.IsDelegated(act) {
		return false
	}

	for _, grant := range parent.Grants() {
		if grant.Category() == Authorize && grant.Action() == act && grant.Node().Equals(sn) {
			return true
		}
	}

	return false
}

func (sn *SQLNode) IsDelegated(act Action) bool {
	if sn.Parent() == nil {
		return false
	}

	tmp := sn.Parent().(*SQLNode)
	orig := sn

	for {
		found := false

		for _, grant := range tmp.Grants() {
			if grant.Category() == Delegate && grant.Action() == act && grant.Node().Equals(orig) {
				found = true
			}
		}

		if !found {
			return false
		}

		if tmp.Parent() != nil {
			orig = tmp
			tmp = sn.Parent().(*SQLNode)
		} else {
			return true
		}
	}

	return false // we should never get here
}

func (sn *SQLNode) Equals(n Node) bool {
	if n == nil {
		return false
	}

	return sn.id == n.(*SQLNode).id
}
