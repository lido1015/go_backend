package api

import (
	"net/http"

	"github.com/NODO-UH/gestion-go/src/auth"
	"github.com/NODO-UH/gestion-go/src/proxy"
	"github.com/gin-gonic/gin"
)

type ProxyQuotaResult struct {
	Bonus    int64 `json:"bonus" binding:"required"`
	Consumed int64 `json:"consumed" binding:"required"`
	Quota    int64 `json:"quota" binding:"required"`
}

// ProxyQuota godoc
// @Summary Get proxy quota
// @Description Get Internet Quota Consumption
// @Tags Proxy
// @Produce json
// @Success 200 {object} ProxyQuotaResult
// @Failure 400 {object} Error
// @Failure 404 {object} Error
// @Failure 500 {object} Error
// @Router /proxy/quota [get]
func ProxyQuota(ctx *gin.Context) {
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
	quota, err := proxy.GetQuota(claims.User)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, Error{
			Code:    ErrProxyGetQuota,
			Message: err.Error(),
		})
		return
	}
	ctx.AbortWithStatusJSON(http.StatusOK, ProxyQuotaResult{
		Quota:    quota.Quota,
		Bonus:    quota.Bonus,
		Consumed: quota.Consumed,
	})
}
