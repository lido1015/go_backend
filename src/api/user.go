package api

import (
	"net/http"

	"github.com/NODO-UH/gestion-go/src/auth"
	"github.com/NODO-UH/gestion-go/src/vpn"

	mongomanager "github.com/NODO-UH/mongo-manager"

	"github.com/NODO-UH/gestion-go/src/ldap"
	"github.com/gin-gonic/gin"
)

type ChangePasswordModel struct {
	NewPassword *string `json:"newPassword" binding:"required"`
	OldPassword *string `json:"oldPassword" binding:"required"`
}

type NewUserModel struct {
	CI        *string                       `json:"ci" binding:"required"`
	Serial    *string                       `json:"serial" binding:"required"`
	Questions *mongomanager.StoredQuestions `json:"questions" binding:"required"`
	Password  *string                       `json:"password" binding:"required"`
}

type UserDataModel struct {
	CI               string `json:"ci" binding:"required"`
	Email            string `json:"email" binding:"required"`
	Name             string `json:"name" binding:"required"`
	ObjectClass      string `json:"objectClass" binding:"required"`
	Position         string `json:"position" binding:"required"`
	CareerName       string `json:"careerName" binding:"required"`
	Salary           string `json:"salary" binding:"required"`
	SubArea          string `json:"subArea" binding:"required"`
	ServiceTime      string `json:"serviceTime" binding:"required"`
	Vacations        string `json:"vacations" binding:"required"`
	SubCategory      string `json:"subCategory" binding:"required"`
	ActiveYears      string `json:"activeYears" binding:"required"`
	CurseType        string `json:"curseType" binding:"required"`
	ScientificDegree string `json:"scientificDegree" binding:"required"`
	Militancy        string `json:"militancy" binding:"required"`
	HasVC            bool   `json:"hasVc" binding:"required"`
	HasInternet      bool   `json:"hasInternet" binding:"required"`
	HasCloud         bool   `json:"hasCloud" binding:"required"`
	HasEmail         bool   `json:"hasEmail" binding:"required"`
	HasVPN           bool   `json:"hasVPN" binding:"required"`
}

type AdminUserDataModel struct {
	UserDataModel
	AlreadySignIn bool `json:"alreadySignIn"`
}

// ChangePassword godoc
// @Summary Change user password.
// @Description Change user password stored in LDAP server.
// @Tags User
// @Accept json
// @Produce json
// @Param newPassword body ChangePasswordModel true "Old and new password"
// @Success 200
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /user/changepassword [post]
func ChangePassword(ctx *gin.Context) {
	claimsI, ok := ctx.Get("jwtClaims")
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	claims, ok := claimsI.(*auth.JwtClaims)
	if !ok {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	var data ChangePasswordModel
	if err := ctx.ShouldBindJSON(&data); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrChangePassword,
			Message: err.Error(),
		})
		return
	}
	if err := ldap.ChangePassword(claims.User, *data.OldPassword, *data.NewPassword); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrChangePassword,
			Message: err.Error(),
		})
		return
	}
	ctx.AbortWithStatus(http.StatusOK)
}

// Me godoc
// @Summary Get User Data.
// @Description Get User Data.
// @Tags userData
// @Produce json
// @Success 200 {object} UserDataModel
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /user/me [get]
func Me(ctx *gin.Context) {
	claimsI, ok := ctx.Get("jwtClaims")
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	claims, ok := claimsI.(*auth.JwtClaims)
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	data, err := ldap.GeUserData(claims.User)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrGettingUserSecurityQuestions,
			Message: err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, UserDataModel{
		Email:            data.Email,
		Name:             data.Name,
		ObjectClass:      data.ObjectClass,
		Position:         data.Position,
		CareerName:       data.CareerName,
		Salary:           data.Salary,
		SubArea:          data.SubArea,
		ServiceTime:      data.ServiceTime,
		Vacations:        data.Vacations,
		SubCategory:      data.SubCategory,
		ActiveYears:      data.ActiveYears,
		CurseType:        data.CurseType,
		ScientificDegree: data.ScientificDegree,
		Militancy:        data.Militancy,
		HasVC:            data.HasVC,
		HasInternet:      data.HasInternet,
		HasCloud:         data.HasCloud,
		HasEmail:         data.HasEmail,
		HasVPN:           data.HasVPN,
	})
}

// GetVPN godoc
// @Summary Get VPN of given user
// @Description Get VPN of given user
// @Tags Admin
// @Accept json
// @Param ci query string false "CI of user to get VPN"
// @Success 200
// @Failure 400 {object} Error
// @Failure 404 {object} Error
// @Failure 500 {object} Error
// @Router /user/getVPN [get]
func GetVPN(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "empty query params",
		})
		return
	}
	claimsI, ok := ctx.Get("jwtClaims")
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	claims, ok := claimsI.(*auth.JwtClaims)
	if !ok {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	vpnString, err := vpn.GetVPN(claims.User, ci)
	if err != nil {
		if err == mongomanager.ErrUserNotFound {
			ctx.AbortWithStatusJSON(http.StatusNotFound, Error{
				Code:    ErrDataInvalid,
				Message: "do not exist VPN for ci " + ci,
			})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: "unexpected server error",
		})
		return
	}
	ctx.Data(http.StatusOK, "application/ovpn", []byte(vpnString))
}

// Search godoc
// @Summary Search user by CI
// @Description Search user by CI
// @Param text query string true "Text with the query data"
// @Success 200
// @Failure 404
// @Router /user/search [get]
func Search(ctx *gin.Context) {
	ci := ctx.Query("ci")
	if ci == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "ci query param is required",
		})
		return
	}
	_, err := ldap.FindByCI(ci, "")
	if err != nil && err != ldap.ErrMultipleUsers {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else {
		ctx.AbortWithStatus(http.StatusOK)
	}
}
