package api

import (
	"net/http"
	"strings"

	"github.com/NODO-UH/gestion-go/src/database"
	"github.com/NODO-UH/gestion-go/src/ldap"
	"github.com/NODO-UH/gestion-go/src/log"

	"github.com/NODO-UH/gestion-go/src/auth"
	"github.com/gin-gonic/gin"
)

type LoginCredentialsModel struct {
	Password *string `json:"password" binding:"required"`
	User     *string `json:"user" binding:"required"`
}

type ResetPasswordModel struct {
	Answers     []string `json:"answers" binding:"required"`
	CI          *string  `json:"ci" binding:"required"`
	Email       *string  `json:"email" binding:"required"`
	NewPassword *string  `json:"newPassword" binding:"required"`
	Questions   []string `json:"questions" binding:"required"`
}

type TokensResult struct {
	Token        *string `json:"token"`
	TokenRefresh *string `json:"tokenRefresh"`
}

// Login godoc
// @Summary Login into system
// @Description Login into system with given credentials. Return two tokens, access and refresh.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param credentials body LoginCredentialsModel true "Credentials"
// @Success 200 {object} TokensResult
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /auth/login [post]
func Login(ctx *gin.Context) {
	credentials := LoginCredentialsModel{}
	if err := ctx.ShouldBindJSON(&credentials); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: err.Error(),
		})
	} else if loginResult, err := auth.LoginUser(*credentials.User, *credentials.Password); loginResult == nil { // Login
		if err == ldap.ErrUserLocked {
			message, err := ldap.GetBlockedDescription(*credentials.User)
			if err != nil {
				log.Err(err.Error(), "[LOGIN]")
				ctx.JSON(http.StatusInternalServerError, Error{
					Code:    ErrUnknown,
					Message: "internal error",
				})
				return
			}
			ctx.JSON(http.StatusUnauthorized, Error{
				Code:    ErrUserLocked,
				Message: message,
			})
			return
		}
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrInvalidCredentials,
			Message: "invalid credentials",
		})
	} else if tokenLogin, err := auth.LoginJwt(&auth.JwtClaims{
		User:        *credentials.User,
		Role:        loginResult.Role,
		Ou:          loginResult.Ou,
		Permissions: loginResult.Permissions,
	}); err != nil { // Generate login JWT
		ctx.JSON(http.StatusInternalServerError, Error{
			Code:    ErrLoginGenerateLoginJWT,
			Message: "error generating login JWT",
		})
	} else if tokenRefresh, err := auth.RefreshJwt(&auth.JwtClaims{
		User:        *credentials.User,
		Role:        loginResult.Role,
		Ou:          loginResult.Ou,
		Permissions: loginResult.Permissions,
	}); err != nil { // Generate refresh JWT
		ctx.JSON(http.StatusInternalServerError, Error{
			Code:    ErrLoginGenerateRefreshJWT,
			Message: "error generating refresh JWT",
		})
	} else { // All ok, response with login JWT and refresh JWT
		ctx.JSON(http.StatusOK, TokensResult{
			Token:        &tokenLogin,
			TokenRefresh: &tokenRefresh,
		})
	}
}

// Refresh godoc
// @Summary Refresh tokens
// @Description Refresh access and refresh tokens
// @Tags Authentication
// @Produce json
// @Param token query string true "refresh token"
// @Success 200 {object} TokensResult
// @Failure 400 {object} Error
// @Failure 500 {object} Error
// @Router /auth/refresh [post]
func Refresh(ctx *gin.Context) {
	// Get refresh tokenStr from query string
	tokenStr := ctx.Query("token")
	if tokenStr == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, Error{
			Code:    ErrDataInvalid,
			Message: "token is required",
		})
		return
	}
	// Validate refresh JWT
	_, claims, err := auth.ValidateToken(tokenStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrRefreshInvalidRefreshJWT,
			Message: "invalid refresh JWT",
		})
		return
	}
	// Generate new login token
	tokenLogin, err := auth.LoginJwt(claims)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		log.Err("error generating login JWT", "[REFRESH]")
		return
	}
	// Generate new refresh token
	tokenRefresh, err := auth.RefreshJwt(claims)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		log.Err("error generating refresh JWT", "[REFRESH]")
		return
	}
	ctx.JSON(http.StatusOK, TokensResult{
		Token:        &tokenLogin,
		TokenRefresh: &tokenRefresh,
	})
}

type SignUpModel struct {
	CI        string   `json:"ci" binding:"required"`
	Password  string   `json:"password" binding:"required"`
	Questions []string `json:"questions" binding:"required"`
	Answers   []string `json:"answers" binding:"required"`
}

type SignUpResult struct {
	UserID string `json:"userId" binding:"required"`
	Ou     string `json:"ou" binding:"required"`
}

// SignUp godoc
// @Summary Sign up new user
// @Description Sign up new user with CI. If user is already enabled, then error is returned.
// @Tags Authentication
// @Consume json
// @Produce json
// @Param signUpData body SignUpModel true "Sign up required data"
// @Success 200 {object} SignUpResult
// @Failure 401 {object} Error
// @Failure 500 {object} Error
// @Router /auth/signup [post]
func SignUp(ctx *gin.Context) {
	data := &SignUpModel{}
	if err := ctx.ShouldBindJSON(data); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrSignUp,
			Message: err.Error(),
		})
	} else if len(data.Answers) != len(data.Questions) {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrInvalidNumberOfQuestions,
			Message: "number of questions and answers not match",
		})
	} else if uid, objectClass, dn, lockedDesc, err := ldap.GetDisableUser(data.CI); err != nil { // Get disable user
		switch err {
		case ldap.ErrUserAlreadyEnabled:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrUserAlreadyEnabled,
				Message: err.Error(),
			})
		case ldap.ErrUserNotFound:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrUserNotFound,
				Message: err.Error(),
			})
		case ldap.ErrUserLocked:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrUserLocked,
				Message: lockedDesc,
			})
		default:
			ctx.JSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
	} else {
		var questions []database.StoredQuestion
		for i, q := range data.Questions {
			questions = append(questions, database.StoredQuestion{
				Question: q,
				Answer:   strings.ToLower(strings.TrimSpace(data.Answers[i])),
			})
		}
		// Set security questions
		if err := database.Management.SetSecurityQuestions(database.StoredQuestions{
			User:      uid,
			Questions: questions,
		}); err != nil {
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		} else if err := ldap.SetPassword(dn, data.Password); err != nil { // Set new password
			switch err {
			case ldap.ErrInvalidCredentials:
				ctx.JSON(http.StatusBadRequest, Error{
					Code:    ErrInvalidCredentials,
					Message: err.Error(),
				})
			default:
				ctx.JSON(http.StatusInternalServerError, Error{
					Code:    ErrUnknown,
					Message: err.Error(),
				})
			}
		} else {
			if err := ldap.EnableServices(dn); err != nil {
				log.Err(err.Error(), "LDAP")
			}

			// Send welcome email
			// cmd := exec.Command("sendmail", "-F", "Nodo Central", "-f", "nodo@uh.cu", uid)

			// cmd.Stdin = bytes.NewReader([]byte(buildWelcomeEmail(uid, data.CI)))
			// cmd.Stderr = os.Stderr
			// _, err := cmd.Output()
			// if err != nil {
			// 	log.Err(err.Error(), "[EMAIL]")
			// }

			ctx.JSON(http.StatusOK, SignUpResult{
				UserID: uid,
				Ou:     objectClass,
			})
		}
	}
}

type ResetPasswordResult struct {
	UserID string `json:"userId" binding:"required"`
}

// ResetPassword godoc
// @Summary Reset Password to user
// @Description Reset password to removed user
// @Tags Authentication
// @Consume json
// @Produce json
// @Param resetPasswordData body ResetPasswordModel true "Reset Password required data"
// @Success 200 {object} ResetPasswordResult
// @Failure 401 {object} Error
// @Failure 500 {object} Error
// @Router /auth/resetpassword [post]
func ResetPassword(ctx *gin.Context) {
	data := &ResetPasswordModel{}
	if err := ctx.ShouldBindJSON(data); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrResettingPassword,
			Message: err.Error(),
		})
	} else if len(data.Answers) != len(data.Questions) {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrInvalidNumberOfQuestions,
			Message: "number of questions and answers not match",
		})
	} else if isLocked, lockedDescription, err := ldap.IsBlocked(*data.Email); isLocked {
		ctx.AbortWithStatusJSON(http.StatusForbidden, Error{
			Code:    ErrUserLocked,
			Message: lockedDescription,
		})
	} else if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, Error{
			Code:    ErrUnknown,
			Message: err.Error(),
		})
	} else if dn, err := ldap.FindByCI(*data.CI, *data.Email); err != nil {
		switch err {
		case ldap.ErrUserNotFound:
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrUserNotFound,
				Message: err.Error(),
			})
		case ldap.ErrMultipleUsers:
			ctx.JSON(http.StatusInternalServerError, Error{
				Code:    ErrMultipleUsers,
				Message: err.Error(),
			})
		default:
			ctx.JSON(http.StatusInternalServerError, Error{
				Code:    ErrUnknown,
				Message: err.Error(),
			})
		}
	} else if userStoredQuestions, err := database.Management.GetUserSecurityQuestions(*data.Email); err != nil {
		ctx.JSON(http.StatusBadRequest, Error{
			Code:    ErrGettingUserSecurityQuestions,
			Message: err.Error(),
		})
	} else {
		for _, userQuestions := range userStoredQuestions.Questions {
			found := false
			for dataQIndex, dataQ := range data.Questions {
				if dataQ == userQuestions.Question && strings.ToLower(strings.TrimSpace(data.Answers[dataQIndex])) == userQuestions.Answer {
					found = true
					break
				}
			}
			if !found {
				ctx.JSON(http.StatusBadRequest, Error{
					Code:    ErrBadSecurityQuestions,
					Message: "bad security questions response",
				})
				return
			}
		}

		if err := ldap.ResetPassword(dn, *data.NewPassword); err != nil {
			ctx.JSON(http.StatusBadRequest, Error{
				Code:    ErrInvalidCredentials,
				Message: err.Error(),
			})
		}

		ctx.JSON(http.StatusOK, ResetPasswordResult{
			UserID: *data.Email,
		})
	}
}
