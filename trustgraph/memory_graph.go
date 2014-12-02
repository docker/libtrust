package trustgraph

import (
	"strings"

	"github.com/docker/libtrust"
)

type permission uint8

var (
	notPermitted = permission(0)
	delegated    = permission(1)
	permitted    = permission(2)
)

type grantNode struct {
	grants   []*Grant
	children map[string]*grantNode
}

type memoryGraph struct {
	roots map[string]*grantNode
}

func newGrantNode() *grantNode {
	return &grantNode{
		grants:   []*Grant{},
		children: map[string]*grantNode{},
	}
}

func grantSameScope(g1, g2 *Grant) bool {
	if g1.Grantee != g2.Grantee {
		return false
	}
	if g1.Subject != g2.Subject {
		return false
	}
	if len(g1.Scopes) != len(g2.Scopes) {
		return false
	}

	// Check if any scopes don't match up
	for s1 := range g1.Scopes {
		var found bool
		for s2 := range g2.Scopes {
			if s1 == s2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true

}

// NewMemoryGraph returns a new in memory trust graph created from
// a static list of grants.  This graph is immutable after creation
// and any alterations should create a new instance.
func NewMemoryGraph(grants []*Grant) TrustGraph {
	roots := map[string]*grantNode{}
	var revocations []*Grant
	for _, grant := range grants {
		if grant.Revoked {
			revocations = append(revocations, grant)
		}
		parts := strings.Split(grant.Grantee, "/")
		nodes := roots
		var node *grantNode
		var nodeOk bool
		for _, part := range parts {
			node, nodeOk = nodes[part]
			if !nodeOk {
				node = newGrantNode()
				nodes[part] = node
			}
			if part != "" {
				node.grants = append(node.grants, grant)
			}
			nodes = node.children
		}
	}
	for _, revocation := range revocations {
		// Only apply revocation on existing grants
		parts := strings.Split(revocation.Grantee, "/")
		nodes := roots
		var node *grantNode
		var nodeOk bool
		for _, part := range parts {
			node, nodeOk = nodes[part]
			if !nodeOk {
				break
			}

			for i, grant := range node.grants {
				if grantSameScope(grant, revocation) {
					if grant.IssuedAt.Before(revocation.IssuedAt) {
						// Replace grant with revocation
						node.grants[i] = revocation
					}
				}
			}
			nodes = node.children
		}
	}
	return &memoryGraph{roots}
}

func (g *memoryGraph) getGrants(name string) []*Grant {
	nameParts := strings.Split(name, "/")
	nodes := g.roots
	var node *grantNode
	var nodeOk bool
	for _, part := range nameParts {
		node, nodeOk = nodes[part]
		if !nodeOk {
			return nil
		}
		nodes = node.children
	}
	return node.grants
}

func isSubName(name, sub string) bool {
	if strings.HasPrefix(name, sub) {
		if len(name) == len(sub) || name[len(sub)] == '/' {
			return true
		}
	}
	return false
}

func getScope(scope string, grant *Grant) permission {
	var isScoped bool
	for _, s := range grant.Scopes {
		if s == "any" || s == scope {
			isScoped = true
		}
	}
	if isScoped {
		if grant.Delegated {
			return delegated
		}
		return permitted
	}
	return notPermitted
}

type walkFunc func(*Grant, []*Grant) bool

func foundWalkFunc(*Grant, []*Grant) bool {
	return true
}

func (g *memoryGraph) walkGrants(start, target string, scope string, f walkFunc, chain []*Grant, visited map[*Grant]bool, collect bool) bool {
	if visited == nil {
		visited = map[*Grant]bool{}
	}
	grants := g.getGrants(start)
	subGrants := make([]*Grant, 0, len(grants))
	for _, grant := range grants {
		if visited[grant] {
			continue
		}
		visited[grant] = true
		permissionScope := getScope(scope, grant)
		if permissionScope == permitted {
			// TODO replace isSubName with isChild
			if isSubName(target, grant.Subject) {
				if f(grant, chain) {
					return true
				}
			}
		} else if permissionScope == delegated {
			if isSubName(target, grant.Subject) {
				if f(grant, chain) {
					return true
				}
			} else {
				subGrants = append(subGrants, grant)
			}
		}
	}
	for _, grant := range subGrants {
		var chainCopy []*Grant
		if collect {
			chainCopy = make([]*Grant, len(chain)+1)
			copy(chainCopy, chain)
			chainCopy[len(chainCopy)-1] = grant
		} else {
			chainCopy = nil
		}

		if g.walkGrants(grant.Subject, target, scope, f, chainCopy, visited, collect) {
			return true
		}
	}
	return false
}

func (g *memoryGraph) Verify(key libtrust.PublicKey, node string, scope string) (bool, error) {
	return g.walkGrants(key.KeyID(), node, scope, foundWalkFunc, nil, nil, false), nil
}

func (g *memoryGraph) GetGrants(key libtrust.PublicKey, node string, scope string) ([][]*Grant, error) {
	grants := [][]*Grant{}
	collect := func(grant *Grant, chain []*Grant) bool {
		grantChain := make([]*Grant, len(chain)+1)
		copy(grantChain, chain)
		grantChain[len(grantChain)-1] = grant
		grants = append(grants, grantChain)
		return false
	}
	g.walkGrants(key.KeyID(), node, scope, collect, nil, nil, true)
	return grants, nil
}
