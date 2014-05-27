package libtrust

import ()

type Graph interface {
	Set(from, to string, cat Category) (Edge, error)
	Get(id string) (Edge, error)
	GetChildren(id string) ([]Edge, error)
	Delete(Edge) error
	DeleteAll(Edge) error
	Walk(Edge, func(Edge))
}

type Edge interface {
	From() string
	To() string
	Cat() Category
	Action() Action
	Neighbours(reverse bool, cat Category) ([]Edge, error)
}

type Category int

const (
	Authorize Category = iota
	Delegate
)

type Action int

// Actions map to Beam commands.
// FIXME: move this to Beam and import it from there.
const (
	LS Action = iota
	CD
	CONNECT
	SET
	GET
	LOG
	STOP
	START
	RM
	REGISTER
	AUTHORIZE
	DELEGATE
	PULL
	PUSH
)
