package graph

func Walk(node Node, nodeFunc func(Node) (bool, error)) (bool, error) {
	for _, child := range node.Children() {
		if ok, err := nodeFunc(child); !ok || err != nil {
			return ok, err
		}

		if ok, err := Walk(child, nodeFunc); !ok || err != nil {
			return ok, err
		}
	}

	return true, nil
}
