package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NODO-UH/gestion-go/src/database"
	"github.com/NODO-UH/gestion-go/src/ldap"
	"github.com/gin-gonic/gin"
)

type BlockUserData struct {
	Email   string `json:"email"`
	Comment string `json:"comment"`
}

// BlockUser godoc
// @Summary Block user
// @Description Disable all services and block user access
// @Tags Admin
// @Accept json
// @Param block body BlockUserData true "Data of the user to block"
// @Success 200
// @Failure 400 {object} Error
// @Failure 402 {object} Error
// @Router /admin/user/block [post]
func BlockUser(ctx *gin.Context) {
	// Parse data
	var data BlockUserData
	if err := ctx.ShouldBindJSON(&data); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: err.Error(),
		})
		return
	}
	// Check if user is already blocked
	if ok, _, err := ldap.IsBlocked(data.Email); ok {
		ctx.Status(http.StatusOK)
		return
	} else if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	start := time.Now().Unix()
	// Set block in LDAP
	err := ldap.PatchByEmail(data.Email, &ldap.PatchData{
		HasEmail:           boolP(false),
		HasInternet:        boolP(false),
		HasVideoConference: boolP(false),
		HasCloud:           boolP(false),
		HasVPN:             boolP(false),
		EsBloqueado:        boolP(true),
		FechaBloqueo:       &start,
		DescripcionBloqueo: &data.Comment,
	})
	if err == ldap.ErrUserNotFound {
		ctx.AbortWithStatusJSON(http.StatusNotFound, Error{
			Code:    ErrUserNotFound,
			Message: fmt.Sprintf("User %s not found in LDAP", data.Email),
		})
		return
	}
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}

	// Insert user to current blocks in the MongoDB
	err = database.Management.AddUserToCurrentBlocks(database.BlockedUserItem{
		UserId:  data.Email,
		Comment: data.Comment,
		Start:   start,
		End:     0,
	})
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	ctx.Status(http.StatusOK)
}

// UnblockUser godoc
// @Summary Unblock user
// @Description Returns the access of the account to the user
// @Tags Admin
// @Accept json
// @Param email query string true "Email of the user to unblock"
// @Failure 400 {object} Error
// @Failure 402 {object} Error
// @Router /admin/user/unblock [post]
func UnblockUser(ctx *gin.Context) {
	email := ctx.Query("email")
	if email == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "email is required",
		})
		return
	}
	// Check if user is already unblocked
	if ok, _, err := ldap.IsBlocked(email); !ok {
		ctx.Status(http.StatusOK)
		return
	} else if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	// Unblock in LDAP
	err := ldap.PatchByEmail(email, &ldap.PatchData{
		HasEmail:           boolP(true),
		HasInternet:        boolP(true),
		HasVideoConference: boolP(false),
		HasCloud:           boolP(false),
		HasVPN:             boolP(false),
		EsBloqueado:        boolP(false),
		FechaBloqueo:       int64P(0),
		DescripcionBloqueo: stringP("-"),
	})
	if err == ldap.ErrUserNotFound {
		ctx.AbortWithStatusJSON(http.StatusNotFound, Error{
			Code:    ErrUserNotFound,
			Message: fmt.Sprintf("User %s not found in LDAP", email),
		})
		return
	}
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	// Remove blocked user from MongoDB and move it to the history of blocks
	err = database.Management.UnblockUser(email)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
		return
	}
	ctx.AbortWithStatus(http.StatusOK)
}
