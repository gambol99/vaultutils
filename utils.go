package vaultutils

//
// containedIn checks if a value in a list of a strings
//
func containedIn(value string, list []string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}

	return false
}
