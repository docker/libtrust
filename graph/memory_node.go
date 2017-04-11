package graph

/*
   Graph is an in-memory implementation of Node.
*/
type MemoryNode struct {
	id       string
	grants   []Grant
	children []Node
	parent   Node
}

func nodeReject(from []Node, item Node) []Node {
	/*
	   FIXME: erikh: this and grantReject should be generic, but my go
	   isn't that good.
	*/

	found := []int{}
	retval := make([]Node, len(from))

	for i, thisChild := range from {
		if thisChild.Equals(item) {
			found = append(found, i)
		}
	}

	origlen := len(from)

	copy(retval, from)

	for _, i := range found {
		i -= origlen - len(retval)

		if i < 0 {
			i = 0
		}

		if i == 0 {
			if len(retval) < 2 {
				return []Node{}
			}

			retval = retval[1:]
		} else if i == len(retval)-1 {
			retval = retval[:i]
		} else {
			retval = append(retval[:i], retval[i+1:]...)
		}
	}

	return retval
}

func (mg *MemoryNode) NewGrant(c Category, a Action, n Node) (Grant, error) {
	grant := MemoryGrant{
		// TODO(obama): yes we
		category: c,
		action:   a,
		node:     n,
	}

	mg.AddGrant(grant)

	return grant, nil
}

func (g *MemoryNode) Equals(other Node) bool {
	return g.Name() == other.Name()
}

func (g *MemoryNode) Name() string {
	return g.id
}

func (g *MemoryNode) Children() []Node {
	return g.children
}

func (g *MemoryNode) AddChild(child Node) error {
	g.children = append(g.children, child)
	return nil
}

func (g *MemoryNode) RemoveChild(child Node) error {
	g.children = nodeReject(g.children, child)
	return nil
}

func (g *MemoryNode) Parent() Node {
	return g.parent
}

func (g *MemoryNode) SetParent(parent Node) error {
	if g.Parent() != nil {
		g.Parent().RemoveChild(g)
	}

	g.parent = parent
	parent.AddChild(g)
	return nil
}

func (g *MemoryNode) AddGrant(grant Grant) error {
	g.grants = append(g.grants, grant.(Grant))
	return nil
}

func (g *MemoryNode) RemoveGrant(grant Grant) error {
	g.grants = grantReject(g.grants, grant)
	return nil
}

func (g *MemoryNode) Grants() []Grant {
	return g.grants
}

func (g *MemoryNode) IsDelegated(act Action) bool {
	if g.Parent() == nil {
		return false
	}

	tmp := g.Parent().(*MemoryNode)
	orig := g

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
			tmp = g.Parent().(*MemoryNode)
		} else {
			return true
		}
	}

	return false // we should never get here
}

func (g *MemoryNode) IsCapable(act Action) bool {
	parent := g.Parent().(*MemoryNode)

	if !parent.IsDelegated(act) {
		return false
	}

	for _, grant := range parent.Grants() {
		if grant.Category() == Authorize && grant.Action() == act && grant.Node().Equals(g) {
			return true
		}
	}

	return false // we should never get here.
}
