package database

import "errors"

var (
	ErrUnexpected       = errors.New("unexpected error, see logs for more information")
	ErrUserNotFound     = errors.New("user not found")
	ErrQuestionNotFound = errors.New("question not found")
	ErrRoleNotFound     = errors.New("role not found")
	ErrInvalidId        = errors.New("invalid id")
)
