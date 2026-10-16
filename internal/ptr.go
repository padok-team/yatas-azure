package internal

// Deref returns the value behind p, or the zero value when p is nil. Azure SDK
// models use pointers for every optional field.
func Deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
