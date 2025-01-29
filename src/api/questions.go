package api

import (
	"net/http"

	"github.com/NODO-UH/gestion-go/src/ldap"
	"github.com/NODO-UH/gestion-go/src/questions"
	"github.com/gin-gonic/gin"
)

type UserCiModel struct {
	CI string `json:"ci" binding:"required"`
}

type SecurityQuestions struct {
	Questions []string `json:"questions" binding:"required"`
}

type StoredQuestionsModel struct {
	Answers   []string `json:"answers" binding:"required"`
	Questions []string `json:"questions" binding:"required"`
	UserId    string   `json:"userId" binding:"required"`
}

// GetSecurityQuestions godoc
// @Summary Get security questions.
// @Description Get available security questions.
// @Tags Questions
// @Produce json
// @Success 200 {object} SecurityQuestions
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /securityquestions [get]
func GetSecurityQuestions(ctx *gin.Context) {
	if q, err := questions.GetSecurityQuestions(); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrGettingSecurityQuestions,
			Message: err.Error(),
		})
	} else {
		ctx.JSON(http.StatusOK, SecurityQuestions{
			Questions: q,
		})
	}
}

// GetUserSecurityQuestions godoc
// @Summary Get user security questions.
// @Description Get user stored security questions.
// @Tags Questions
// @Accept json
// @Produce json
// @Param ci query string true "ci"
// @Param ci query string true "email"
// @Success 200 {object} SecurityQuestions
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /user/securityquestions [get]
func GetUserSecurityQuestions(ctx *gin.Context) {
	if ci := ctx.Query("ci"); ci == "" {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "ci not found",
		})
	} else if email := ctx.Query("email"); email == "" {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "ci not found",
		})
	} else if _, err := ldap.FindByCI(ci, email); err != nil {
		switch err {
		case ldap.ErrMultipleUsers:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrMultipleUsers,
				Message: err.Error(),
			})
		case ldap.ErrUserNotFound:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrUserNotFound,
				Message: err.Error(),
			})
		default:
			ctx.JSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
	} else if question, err := questions.GetUserSecurityQuestions(email); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrGettingUserSecurityQuestions,
			Message: err.Error(),
		})
	} else {
		var response []string
		for _, q := range question.Questions {
			response = append(response, q.Question)
		}
		ctx.JSON(http.StatusOK, SecurityQuestions{
			Questions: response,
		})
	}
}
