package auth

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
)

var issuer string

func init() {
	issuer = "gestion-uh"
}

type JwtClaims struct {
	User        string   `json:"user"`
	Role        string   `json:"role"`
	Ou          string   `json:"ou"`
	IsRefresh   bool     `json:"isRefresh"`
	Permissions []string `json:"permissions"`
	jwt.StandardClaims
}

func TokenClaimsFromToken(token *jwt.Token) (*JwtClaims, error) {
	panic("implement me")
}

func LoginJwt(claims *JwtClaims) (string, error) {
	claims.IsRefresh = false
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if t, err := token.SignedString([]byte(getSecretKey())); err != nil {
		return "", err
	} else {
		return t, nil
	}
}

func RefreshJwt(claims *JwtClaims) (string, error) {
	claims.IsRefresh = true
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if t, err := token.SignedString([]byte(getSecretKey())); err != nil {
		return "", err
	} else {
		return t, nil
	}
}

func ValidateToken(encodedToken string) (*jwt.Token, *JwtClaims, error) {
	var claims JwtClaims
	token, err := jwt.ParseWithClaims(encodedToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, isValid := token.Method.(*jwt.SigningMethodHMAC); !isValid {
			return nil, fmt.Errorf("invalid signing method %s", token.Header["alg"])
		}
		return []byte(getSecretKey()), nil
	})
	if !token.Valid {
		return nil, nil, fmt.Errorf("invalid token")
	}
	return token, &claims, err
}

func getSecretKey() string {
	secret := os.Getenv("SECRET")
	if secret == "" {
		secret = "secret"
	}
	return secret
}
