package graph

import (
	"database/sql"
	"errors"
	"fmt"
)

var (
	CLEANUP_QUERIES = []string{
		"delete from nodes where name=?",
		"delete from grants where parent=?",
		"delete from node_parents where name=?",
	}
)

type SQLNavigator struct {
	db *sql.DB
}

func NewSQLNavigator(db *sql.DB) *SQLNavigator {
	return &SQLNavigator{
		db: db,
	}
}

func (s *SQLNavigator) execute(query string, args ...interface{}) (sql.Result, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}

	res, err := tx.Exec(query, args...)
	if err != nil {
		return nil, err
	}

	if count, err := res.RowsAffected(); err != nil || count == 0 {
		return nil, errors.New(fmt.Sprintf("No rows affected by query: %s with args %+v", query, args))
	}

	err = tx.Commit()
	return res, err
}

func (s *SQLNavigator) Set(node Node) error {
	if node, _ := s.Get(node.(*SQLNode).id); node != nil {
		return nil
	}

	if _, err := s.execute("insert into nodes (name) values (?)", node.(*SQLNode).id); err != nil {
		return err
	}

	if _, err := s.execute("insert into node_parents (parent_name, name) values (NULL, ?)", node.(*SQLNode).id); err != nil {
		return err
	}

	return node.(*SQLNode).Commit()
}

func (s *SQLNavigator) Get(id string) (Node, error) {
	row := s.db.QueryRow("select name from nodes where name=?", id)

	var name string

	if err := row.Scan(&name); err != nil {
		return nil, err
	}

	return &SQLNode{
		id:  name,
		nav: s,
	}, nil
}

func (s *SQLNavigator) Delete(id string) error {
	for _, query := range CLEANUP_QUERIES {
		if _, err := s.execute(query, id); err != nil {
			return err
		}
	}

	return nil
}

func (s *SQLNavigator) NewNode(id string) Node {
	node := &SQLNode{
		id:  id,
		nav: s,
	}

	s.Set(node)

	return node
}
