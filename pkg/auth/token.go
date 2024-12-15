package auth

import (
	"fmt"
	"math/rand"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func randomString(n int) string {

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func newRefreshToken() (string, string) {
	key := randomString(5)
	return fmt.Sprintf("%s.%s", randomString(15), key), key
}

func createSignedAccessToken(id, minutes int, ip, key, matchingKey string) (string, error) {
	claims := jwt.MapClaims{
		"iss":          "authApp",
		"user_id":      id,
		"ip":           ip,
		"matching_key": matchingKey,
		"exp":          jwt.NewNumericDate(time.Now().Add(time.Duration(minutes) * time.Minute)),
		"iat":          jwt.NewNumericDate(time.Now()),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	signedAccessToken, err := accessToken.SignedString([]byte(key))
	if err != nil {
		return "", err
	}

	return signedAccessToken, nil
}
