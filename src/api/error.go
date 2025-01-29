package api

// ===============
// API error codes
// ===============

type ErrCode int

const (
	ErrDataInvalid                  = 1
	ErrInvalidCredentials           = 2
	ErrLoginGenerateLoginJWT        = 3
	ErrLoginGenerateRefreshJWT      = 4
	ErrRefreshInvalidRefreshJWT     = 5
	ErrJWTGetClaims                 = 6
	ErrProxyGetQuota                = 7
	ErrChangePassword               = 8
	ErrGettingSecurityQuestions     = 9
	ErrSettingSecurityQuestions     = 10
	ErrGettingUserSecurityQuestions = 11
	ErrInvalidNumberOfAnswers       = 12
	ErrInvalidNumberOfQuestions     = 13
	ErrSignUp                       = 14
	ErrUserAlreadyEnabled           = 15
	ErrUserNotFound                 = 16
	ErrUnknown                      = 17
	ErrMultipleUsers                = 18
	ErrResettingPassword            = 19
	ErrBadSecurityQuestions         = 20
	ErrUserLocked                   = 21
)

type Error struct {
	Code    ErrCode `json:"code" binding:"required"`
	Message string  `json:"message" binding:"required"`
}
