package api

func boolP(x bool) *bool {
	return &x
}

func int64P(x int64) *int64 {
	return &x
}

func stringP(x string) *string {
	return &x
}
