package auth

import (
	"github.com/NODO-UH/gestion-go/src/database"
	"github.com/NODO-UH/gestion-go/src/ldap"
)

type LoginResult struct {
	Role        string
	Ou          string
	Permissions []string
}

func LoginUser(user string, password string) (*LoginResult, error) {
	// Check user and password from LDAP
	if ou, err := ldap.AuthenticateUser(user, password); err == nil {
		role, err := database.Management.GetUserRole(user, true)
		if err != nil {
			return nil, err
		}
		result := &LoginResult{
			Role: "user",
			Ou:   *ou,
		}
		if role != nil {
			result.Role = role.Name
			result.Permissions = make([]string, len(role.Permissions))
			for i, p := range role.Permissions {
				result.Permissions[i] = string(p)
			}
		}
		return result, nil
	} else {
		return nil, err
	}
}
