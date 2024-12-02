package auth

import (
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func createCookieWithAccessToken(id int, ip, key string) (*http.Cookie, error) {
	expTime := time.Now().Add(30 * time.Minute)
	claims := jwt.MapClaims{
		"iss":     "authApp",
		"user_id": id,
		"ip":      ip,
		"exp":     jwt.NewNumericDate(expTime),
		"iat":     jwt.NewNumericDate(time.Now()),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	signedAccessToken, err := accessToken.SignedString([]byte(key))
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     "access_token",
		Value:    signedAccessToken,
		HttpOnly: true,
		Path:     "/api/some_url",
		Expires:  expTime,
	}, nil
}

func createCookieWithRefreshToken(id int, ip, key, refreshID string) (*http.Cookie, error) {
	expTime := time.Now().AddDate(0, 2, 0)
	claims := jwt.MapClaims{
		"iss":        "authApp",
		"user_id":    id,
		"refresh_id": refreshID,
		"ip":         ip,
		"exp":        jwt.NewNumericDate(expTime),
		"iat":        jwt.NewNumericDate(time.Now()),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(key))
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     "refresh_token",
		Value:    signedRefreshToken,
		HttpOnly: true,
		Path:     "/api/refresh",
		Expires:  expTime,
	}, nil
}
