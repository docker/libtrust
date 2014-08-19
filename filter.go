package libtrust

import (
	"path/filepath"
)

func FilterByHosts(keys []PublicKey, host string, includeEmpty bool) ([]PublicKey, error) {
	filtered := make([]PublicKey, 0, len(keys))
	for i := range keys {
		var hosts interface{}
		switch k := keys[i].(type) {
		case *ecPublicKey:
			hosts = k.GetExtendedField("hosts")
		case *rsaPublicKey:
			hosts = k.GetExtendedField("hosts")
		default:
			continue
		}
		hostList, ok := hosts.([]interface{})
		if !ok || (ok && len(hostList) == 0) {
			if includeEmpty {
				filtered = append(filtered, keys[i])
			}
			continue
		}
		// Check if any hostList match pattern
		for _, h := range hostList {
			hString, ok := h.(string)
			if !ok {
				continue
			}
			match, matchErr := filepath.Match(hString, host)
			if matchErr != nil {
				return nil, matchErr
			}
			if match {
				filtered = append(filtered, keys[i])
				continue
			}
		}

	}
	return filtered, nil
}
