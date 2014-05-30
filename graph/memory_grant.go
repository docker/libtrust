package graph

type MemoryGrant struct {
	action   Action
	category Category
	node     Node
}

func grantReject(from []Grant, item Grant) []Grant {
	found := []int{}
	retval := make([]Grant, len(from))

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
				return []Grant{}
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

func (grant MemoryGrant) Equals(other Grant) bool {
	return (grant.Category() == other.Category() &&
		grant.Action() == other.Action() &&
		grant.Node().Equals(other.Node()))
}

func (grant MemoryGrant) Category() Category {
	return grant.category
}

func (grant MemoryGrant) Action() Action {
	return grant.action
}

func (grant MemoryGrant) Node() Node {
	return grant.node
}

func (grant MemoryGrant) SetCategory(c Category) error {
	grant.category = c
	return nil
}

func (grant MemoryGrant) SetAction(a Action) error {
	grant.action = a
	return nil
}

func (grant MemoryGrant) SetNode(n Node) error {
	grant.node = n
	return nil
}
