package api

import (
	_ "embed"
	"fmt"
)

//go:embed welcome-email.txt
var welcomeEmail string

func buildWelcomeEmail(user, ci string) string {
	return fmt.Sprintf(welcomeEmail, user)
}
