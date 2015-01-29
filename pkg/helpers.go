package pkg

import "github.com/hooklift/oauth2/types"

// StringifyScopes is a helper function to stringify scope structs
func StringifyScopes(scopes []types.Scope) string {
	if len(scopes) <= 0 {
		return ""
	}

	var scope string
	for _, v := range scopes {
		scope += v.ID + " "
	}
	return scope[:len(scope)-1] // removes last space
}
