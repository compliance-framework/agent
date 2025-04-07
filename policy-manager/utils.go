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
