package api

import (
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/NODO-UH/gestion-go/src/database"
	"github.com/NODO-UH/gestion-go/src/ldap"
	"github.com/NODO-UH/gestion-go/src/vpn"
	mongomanager "github.com/NODO-UH/mongo-manager"
	"github.com/gin-gonic/gin"
)

var emailRegexp = regexp.MustCompile(".*@.*")

type VPNProfile struct {
	Profile string `json:"vpnProfile"`
}

type Reset struct {
	Ci    string `json:"ci"`
	Email string `json:"email"`
}

type UserDetailsModel struct {
	AccountsDetails []AdminUserDataModel `json:"accountsDetails"`
	InSystem        bool                 `json:"inSystem"`
}

type ForceChangePasswordModel struct {
	Email       *string `json:"email" binding:"required"`
	NewPassword *string `json:"newPassword" binding:"required"`
}

type RoleModel struct {
	Id   string
	Name string
}

type ChangeEmailData struct {
	CurrentEmail string `json:"currentEmail,omitempty"`
	NewEmail     string `json:"newEmail,omitempty"`
}

type StatusVPNResult struct {
	HasVPN    bool `json:"hasVPN"`
	EnableVPN bool `json:"enableVPN"`
}

// GetRoles godoc
// @Summary Get available roles.
// @Description Get available roles.
// @Tags Admin
// @Success 200 {object} []RoleModel
// @Failure 500 {object} Error
// @Router /admin/roles [get]
func GetRoles(ctx *gin.Context) {
	if roles, err := database.Management.GetRoles(); err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
	} else {
		var out []RoleModel
		for _, r := range roles {
			out = append(out, RoleModel{
				r.Id,
				r.Name,
			})
		}
		ctx.JSON(http.StatusOK, out)
	}
}

// ResetUser godoc
// @Summary Reset user password.
// @Description Reset user and clear password
// @Tags Admin
// @Accept json
// @Param reset body Reset true "CI and Email of user to reset"
// @Success 200
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/reset [post]
func ResetUser(ctx *gin.Context) {
	data := Reset{}
	if err := ctx.ShouldBindJSON(&data); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "ci not found",
		})
	} else if err := ldap.ResetUser(data.Ci, data.Email); err != nil {
		ctx.JSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: "unexpected error",
		})
	} else {
		ctx.Status(http.StatusOK)
	}
}

// GetUserInfo godoc
// @Summary Get User Info by CI.
// @Description GetUserInfo from user front the CI
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to get info"
// @Param uid query string false "UID of user to get info"
// @Success 200 {object} UserDetailsModel
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user [get]
func GetUserInfo(ctx *gin.Context) {
	ci := ctx.Query("ci")
	uid := ctx.Query("uid")
	if ci == "" && uid == "" {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "empty query params",
		})
	} else if accountDetails, inSystem, err := ldap.GetAdminUserData(ci, uid); err != nil {
		ctx.JSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: "unexpected error",
		})
	} else if !inSystem {
		ctx.JSON(http.StatusOK, UserDetailsModel{
			InSystem: false,
		})
	} else {
		userDataModel := make([]AdminUserDataModel, 0)
		for _, account := range accountDetails {
			userDataModel = append(userDataModel, AdminUserDataModel{
				UserDataModel: UserDataModel{
					CI:          account.CI,
					Email:       account.Email,
					Name:        account.Name,
					ObjectClass: account.ObjectClass,
					Position:    account.Position,
					CareerName:  account.CareerName,
					HasInternet: account.HasInternet,
					HasCloud:    account.HasCloud,
					HasEmail:    account.HasEmail,
					HasVPN:      account.HasVPN,
				},
				AlreadySignIn: account.AlreadySignIn,
			})
		}
		ctx.JSON(http.StatusOK, UserDetailsModel{
			AccountsDetails: userDataModel,
			InSystem:        true,
		})
	}
}

// SetUserRole godoc
// @Summary Set role to user
// @Description Set role to user with id user
// @Tags Admin
// @Accept json
// @Param user query string true "email of the user"
// @Param roleId query string true "roleId to assign"
// @Success 200
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/role [post]
func SetUserRole(ctx *gin.Context) {
	if userId := ctx.Query("user"); userId == "" {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "user param is required",
		})
	} else if roleId := ctx.Query("roleId"); roleId == "" {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "roleId param is required",
		})
	} else if err := ldap.UserExists(userId); err != nil {
		switch err {
		case ldap.ErrUserNotFound:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrDataInvalid,
				Message: "user not found",
			})
		default:
			ctx.JSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
	} else if err := database.Management.SetRole(userId, roleId); err != nil {
		switch err {
		case mongomanager.ErrRoleNotFound:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrDataInvalid,
				Message: "role not found",
			})
		default:
			ctx.JSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
	} else {
		ctx.Status(http.StatusOK)
	}
}

// ForceChangePassword godoc
// @Summary Change user password by admin
// @Description Change user password stored in LDAP server.
// @Tags Admin
// @Accept json
// @Produce json
// @Param newPassword body ForceChangePasswordModel true "Account and new Password"
// @Success 200
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/changepassword [post]
func ForceChangePassword(ctx *gin.Context) {
	data := &ForceChangePasswordModel{}
	if err := ctx.ShouldBindJSON(data); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrChangePassword,
			Message: err.Error(),
		})
	}
	if err := ldap.ForcedChangePassword(*data.Email, *data.NewPassword); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrChangePassword,
			Message: err.Error(),
		})
	}
	ctx.AbortWithStatus(http.StatusOK)
}

// ChangeUserEmail godoc
// @Summary Change user email
// @Description Change user email, only if the new email are available
// @Tags Admin
// @Accept json
// @Param data body ChangeEmailData true "current email and the new email"
// @Success 200
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/changeEmail [post]
func ChangeUserEmail(ctx *gin.Context) {
	// Unmarshal data from body request
	var data ChangeEmailData
	err := ctx.ShouldBindJSON(&data)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "invalid request body format",
		})
		return
	}

	// Check params
	if data.CurrentEmail == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "currentEmail is required",
		})
		return
	}
	if data.NewEmail == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "currentEmail is required",
		})
		return
	}
	if !emailRegexp.MatchString(data.NewEmail) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "newEmail is not a valid email address",
		})
		return
	}

	// Check if CurrentEmail exists
	err = ldap.UserExists(data.CurrentEmail)
	if err != nil {
		switch err {
		case ldap.ErrUserNotFound:
			ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
				Code:    ErrUserNotFound,
				Message: fmt.Sprintf("user with email %s do not exists", data.CurrentEmail),
			})
		case ldap.ErrMultipleUsers:
			ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
				Code:    ErrMultipleUsers,
				Message: fmt.Sprintf("exists multiple users with email %s", data.CurrentEmail),
			})
		default:
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
		return
	}

	// Check if NewEmail do not exists
	err = ldap.UserExists(data.NewEmail)
	if err != ldap.ErrUserNotFound {
		if err == nil || err == ldap.ErrMultipleUsers {
			// NewEmail already exists
			ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
				Code:    ErrDataInvalid,
				Message: fmt.Sprintf("user with email %s already exists", data.NewEmail),
			})
		} else {
			// Unexpected error
			ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
		return
	}

	// Change email in LDAP
	err = ldap.ChangeEmail(data.CurrentEmail, data.NewEmail)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}

	// Change email in databases
	err = database.Management.ChangeUserEmail(data.CurrentEmail, data.NewEmail)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	err = database.Proxy.ChangeUserEmail(data.CurrentEmail, data.NewEmail)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
}

// CreateVPN godoc
// @Summary Create VPN of given user
// @Description Create VPN of given user
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to get VPN"
// @Success 200 {object} VPNProfile
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/createVPN [post]
func CreateVPN(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "empty query params",
		})
	} else {
		response, err := vpn.CreateVPN(ci)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		} else {
			ctx.JSON(http.StatusOK, &VPNProfile{
				Profile: response,
			})
		}
	}
}

// DeleteVPN godoc
// @Summary Delete VPN of given user
// @Description Delete VPN of given user
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to get VPN"
// @Success 200
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/deleteVPN [post]
func DeleteVPN(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "empty query params",
		})
		return
	}
	err := ldap.SetVPN(ci, false)
	if err != nil {
		if err == ldap.ErrUserNotFound {
			ctx.AbortWithStatusJSON(http.StatusNotFound, Error{
				Code:    ErrUserNotFound,
				Message: "user not found with",
			})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
	}

	err = vpn.DeleteVPN(ci)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, nil)
}

// EnableVPN godoc
// @Summary Enable VPN of given user
// @Description Enable VPN of given user
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to enable VPN"
// @Success 200
// @Failure 400 {object} Error
// @Failure 404 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/enableVPN [post]
func EnableVPN(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "ci query param is required",
		})
		return
	}
	err := vpn.EnableVPN(ci)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: "unexpected server error",
		})
	}
	ctx.Status(http.StatusOK)
}

// DisableVPN godoc
// @Summary Disable VPN of given user
// @Description Disable VPN of given user
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to disable VPN"
// @Success 200
// @Failure 400 {object} Error
// @Failure 404 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/disableVPN [post]
func DisableVPN(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "ci query param is required",
		})
		return
	}
	err := vpn.DisableVPN(ci)
	if err != nil {
		log.Println(err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: "unexpected server error",
		})
		return
	}
	ctx.Status(http.StatusOK)
}

// StatusVPN godoc
// @Summary Check if the use has a VPN created
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to check VPN"
// @Success 200 {object} StatusVPNResult
// @Failure 400 {object} Error
// @Failure 404 {object} Error
// @Failure 500 {object} Error
// @Router /admin/user/statusVPN [get]
func StatusVPN(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "query param required: ci",
		})
		return
	}
	hasVPN, err := vpn.HasVPN(ci)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}

	enabledVPN, _ := ldap.VPNEnabled(ci)

	ctx.JSON(http.StatusOK, StatusVPNResult{
		HasVPN:    hasVPN,
		EnableVPN: enabledVPN,
	})
}

type EditServicesStatusData struct {
	HasEmail           *bool `json:"hasEmail"`
	HasInternet        *bool `json:"hasInternet"`
	HasVideoConference *bool `json:"hasVideoConference"`
	HasCloud           *bool `json:"hasCloud"`
	HasVPN             *bool `json:"hasVpn"`
}

// EditServicesStatus godoc
// @Summary Edit user services status
// @Tags Admin
// @Accept json
// @Param data body EditServicesStatusData true "patch data"
// @Success 200
// @Failure 400 {object} Error
// @Router /admin/user/editServices [patch]
func EditServicesStatus(ctx *gin.Context) {
	email := ctx.Query("email")
	if email == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, &Error{
			Code:    ErrDataInvalid,
			Message: "email is required",
		})
		return
	}

	var data EditServicesStatusData
	if err := ctx.ShouldBindJSON(&data); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, &Error{
			Code:    ErrDataInvalid,
			Message: err.Error(),
		})
		return
	}

	err := ldap.PatchByEmail(email, &ldap.PatchData{
		HasEmail:           data.HasEmail,
		HasInternet:        data.HasInternet,
		HasVideoConference: data.HasVideoConference,
		HasCloud:           data.HasCloud,
		HasVPN:             data.HasVPN,
	})
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, &Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	ctx.AbortWithStatus(http.StatusOK)
}

// ResetWorkers godoc
// @Summary Reset worker password
// @Tags Admin
// @Accept json
// @Success 200
// @Failure 400 {object} Error
// @Router /admin/reset/workers [post]
func ResetWorkers(ctx *gin.Context) {
	out, err := ldap.ResetWorkers()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, &Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	ctx.AbortWithStatusJSON(http.StatusOK, out)
}
