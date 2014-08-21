package libtrust

import (
	"path/filepath"
)

// FilterByHosts does something.
func FilterByHosts(keys []PublicKey, host string, includeEmpty bool) ([]PublicKey, error) {
	filtered := make([]PublicKey, 0, len(keys))

	for _, pubKey := range keys {
		hosts, ok := pubKey.GetExtendedField("hosts").([]string)

		if !ok || (ok && len(hosts) == 0) {
			if includeEmpty {
				filtered = append(filtered, pubKey)
			}
			continue
		}

		// Check if any hosts match pattern
		for _, hostPattern := range hosts {
			match, err := filepath.Match(hostPattern, host)
			if err != nil {
				return nil, err
			}

			if match {
				filtered = append(filtered, pubKey)
				continue
			}
		}

	}

	return filtered, nil
}
