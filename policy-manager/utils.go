package policy_manager

func MergeMaps[K comparable, V comparable](maps ...map[K]V) map[K]V {
	result := make(map[K]V)
	for _, imap := range maps {
		for k, v := range imap {
			result[k] = v
		}
	}
	return result
}

func Pointer[K interface{}](input K) *K {
	return &input
}

// FirstOf will return the first pointer which is not null.
// This is used when multiple optional options exist to fill a field, but they have an order of priority
func FirstOf[K interface{}](inputs ...*K) *K {
	for _, input := range inputs {
		if input != nil {
			return input
		}
	}
	return nil
}
