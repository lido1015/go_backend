package api

import (
	"strings"

	"github.com/NODO-UH/gestion-go/src/database"
)

const (
	RoleList           = "Role.List"
	UserInfo           = "User.Info"
	UserReset          = "User.Reset"
	UserSetRole        = "User.SetRole"
	UserChangeEmail    = "User.ChangeEmail"
	UserChangePassword = "User.ChangePassword"
	UserModifyVPN      = "User.ChangeVPN"
	UserToggleServices = "User.ToggleServices"
	UserBlock          = "User.Block"
	UserUnblock        = "User.Unblock"
	ResetOu            = "Reset.Ou"
)

func HaveAccess(path string, permissions []database.Permission) bool {
	switch path {
	case "/admin/roles":
		return havePermission(RoleList, permissions)
	case "/admin/user":
		return havePermission(UserInfo, permissions)
	case "/admin/user/reset":
		return havePermission(UserReset, permissions)
	case "/admin/user/role":
		return havePermission(UserSetRole, permissions)
	case "/admin/user/changepassword":
		return havePermission(UserChangePassword, permissions)
	case "/admin/user/changeEmail":
		return havePermission(UserChangeEmail, permissions)
	case "/admin/user/createVPN":
		return havePermission(UserModifyVPN, permissions)
	case "/admin/user/deleteVPN":
		return havePermission(UserModifyVPN, permissions)
	case "/admin/user/enableVPN":
		return havePermission(UserModifyVPN, permissions)
	case "/admin/user/disableVPN":
		return havePermission(UserModifyVPN, permissions)
	case "/admin/user/statusVPN":
		return havePermission(UserModifyVPN, permissions)
	case "/admin/user/editServices":
		return havePermission(UserToggleServices, permissions)
	case "/admin/user/block":
		return havePermission(UserBlock, permissions)
	case "/admin/user/unblock":
		return havePermission(UserUnblock, permissions)
	case "/admin/reset/workers":
		return havePermission(ResetOu, permissions)
	default:
		return false
	}
}

func havePermission(permission database.Permission, permissions []database.Permission) bool {
	for _, p := range permissions {
		if strings.Compare(string(permission), string(p)) == 0 {
			return true
		}
	}
	return false
}
