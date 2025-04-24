package api

import (
	"net/http"

	"github.com/NODO-UH/gestion-go/src/auth"
	"github.com/NODO-UH/gestion-go/src/email"
	"github.com/gin-gonic/gin"
)

type EmailQuotaResult struct {
	Consumed int64 `json:"consumed" binding:"required"`
	Quota    int64 `json:"quota" binding:"required"`
}

// EmailQuota godoc
// @Summary Get email buzon quota
// @Description Get email buzon quota
// @Tags Email
// @Produce json
// @Success 200 {object} EmailQuotaResult
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /email/quota [get]
func EmailQuota(ctx *gin.Context) {
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
	quota, err := email.GetQuota(claims.User, claims.Ou)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrProxyGetQuota,
			Message: err.Error(),
		})
		return
	}
	ctx.AbortWithStatusJSON(http.StatusOK, EmailQuotaResult{
		Quota:    quota.Quota,
		Consumed: quota.Consumed,
	})
}
