package graph

import (
	"errors"
)

type SQLGrant struct {
	id       uint
	action   Action
	category Category
	node     Node
	parent   *SQLNode
	nav      *SQLNavigator
}

func (grant *SQLGrant) Reload() error {
	if grant.id != 0 {
		row := grant.nav.db.QueryRow("select category, action, node, parent from grants where id=?", grant.id)

		var node string
		var parent interface{}

		err := row.Scan(&grant.category, &grant.action, &node, &parent)

		if err != nil {
			return err
		}

		grant.node, err = grant.nav.Get(node)
		if err != nil {
			return err
		}

		if parent != nil {
			parent_obj, err := grant.nav.Get(string(parent.([]byte)))
			if err != nil {
				return err
			}

			grant.parent = parent_obj.(*SQLNode)
		}
	} else {
		return errors.New("Grant does not have an id -- did this grant ever get written?")
	}

	return nil
}

func (grant *SQLGrant) Commit() error {
	var parent interface{}

	if grant.id != 0 {
		if grant.parent != nil {
			parent = grant.parent.Name()
		}

		_, err := grant.nav.execute(
			"update grants set category=?, action=?, node=?, parent=? where id=?",
			grant.category,
			grant.action,
			grant.node.Name(),
			parent,
			grant.id,
		)
		if err != nil {
			return err
		}
	} else {
		if grant.parent != nil {
			parent = grant.parent.Name()
		}

		res, err := grant.nav.execute(
			"insert into grants (parent, node, action, category) values (?, ?, ?, ?)",
			parent,
			grant.node.Name(),
			grant.action,
			grant.category,
		)
		if err != nil {
			return err
		}

		id, err := res.LastInsertId()
		if err != nil {
			return err
		}

		grant.id = uint(id)
	}

	return grant.Reload()
}

func (grant *SQLGrant) Delete() error {
	if grant.id != 0 {
		if _, err := grant.nav.execute("delete from grants where id=?", grant.id); err != nil {
			return err
		}
	} else {
		return errors.New("Grant does not exist")
	}

	return nil
}

func (grant *SQLGrant) Equals(other Grant) bool {
	return (grant.Category() == other.Category() &&
		grant.Action() == other.Action() &&
		grant.Node().Equals(other.Node()))
}

func (grant *SQLGrant) Category() Category {
	return grant.category
}

func (grant *SQLGrant) setItem(query string, args ...interface{}) error {

	if grant.id == 0 {
		err := grant.Commit()
		if err != nil {
			return err
		}
	}

	_, err := grant.nav.execute(query, args...)

	if err != nil {
		return err
	}

	return grant.Reload()
}

func (grant *SQLGrant) SetCategory(c Category) error {
	return grant.setItem("update grants set category=? where id=?", c, grant.id)
}

func (grant *SQLGrant) Action() Action {
	return grant.action
}

func (grant *SQLGrant) SetAction(a Action) error {
	return grant.setItem("update grants set action=? where id=?", a, grant.id)
}

func (grant *SQLGrant) Node() Node {
	return grant.node
}

func (grant *SQLGrant) SetNode(n Node) error {
	return grant.setItem("update grants set action=? where id=?", n.Name(), grant.id)
}
