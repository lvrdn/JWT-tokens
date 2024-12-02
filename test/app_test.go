package test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var key = "anotherKey123!*"

type AuthTestCase struct {
	GUID         string
	Path         string
	CookieUpdate func(*http.Cookie) *http.Cookie
	NumCookieSt  int
	Expected     Response
}

type Response struct {
	StatusCode int
	GetCookies bool
}

func TestApp(t *testing.T) {
	cookiesStorage := make(map[int][]*http.Cookie)
	cases := []*AuthTestCase{
		{ //0. получение access и refresh токенов, guid, которого нет в бд
			GUID: uuid.New().String(),
			Path: "http://127.0.0.1:8080/api/auth?guid=",
			Expected: Response{
				StatusCode: http.StatusBadRequest,
			},
		},
		{ //1. получение access и refresh токенов, guid, который есть в бд
			GUID: "da92d676-1fa8-479f-84ac-68e0a6f0460f",
			Path: "http://127.0.0.1:8080/api/auth?guid=",
			Expected: Response{
				StatusCode: http.StatusOK,
				GetCookies: true,
			},
		},
		{ //2. попытка обновить пару токенов, в запросе нет cookie с refresh токеном
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusBadRequest,
			},
		},
		{ //3. попытка обновить пару токенов, у refresh токена истекло время жизни
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			NumCookieSt: 1,
			CookieUpdate: func(cookie *http.Cookie) *http.Cookie {
				claims := jwt.MapClaims{}
				_, _ = jwt.ParseWithClaims(
					cookie.Value,
					&claims,
					func(token *jwt.Token) (interface{}, error) {
						return []byte(key), nil
					},
				)

				claims["exp"] = claims["iat"] //время жизни == времени выдачи, т.е. токен уже "протух"
				refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
				signedRefreshToken, _ := refreshToken.SignedString([]byte(key))

				return &http.Cookie{
					Name:     cookie.Name,
					Value:    signedRefreshToken,
					HttpOnly: cookie.HttpOnly,
					Path:     cookie.Path,
					Expires:  cookie.Expires,
				}
			},
		},
		{ //4. попытка обновить пару токенов, у refresh токена id, отличный от того, что хранится в базе (проверка на "одноразовость" токена)
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			NumCookieSt: 1,
			CookieUpdate: func(cookie *http.Cookie) *http.Cookie {
				claims := jwt.MapClaims{}
				_, _ = jwt.ParseWithClaims(
					cookie.Value,
					&claims,
					func(token *jwt.Token) (interface{}, error) {
						return []byte(key), nil
					},
				)

				claims["refresh_id"] = uuid.New().String() //новый случайный id refresh токена
				refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
				signedRefreshToken, _ := refreshToken.SignedString([]byte(key))

				return &http.Cookie{
					Name:     cookie.Name,
					Value:    signedRefreshToken,
					HttpOnly: cookie.HttpOnly,
					Path:     cookie.Path,
					Expires:  cookie.Expires,
				}
			},
		},
		{ //5. попытка обновить пару токенов, у refresh токена изменен payload
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			NumCookieSt: 1,
			CookieUpdate: func(cookie *http.Cookie) *http.Cookie {
				refreshToken := cookie.Value
				s := strings.Split(refreshToken, ".")
				payload, _ := base64.StdEncoding.DecodeString(s[1])
				newPayload := strings.ReplaceAll(string(payload), "authApp", "unknownApp") //изменение payload
				s[1] = base64.StdEncoding.EncodeToString([]byte(newPayload))

				return &http.Cookie{
					Name:     cookie.Name,
					Value:    strings.Join(s, "."),
					HttpOnly: cookie.HttpOnly,
					Path:     cookie.Path,
					Expires:  cookie.Expires,
				}
			},
		},
		{ //6. обновление пары токенов, правильный refresh токен
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusOK,
				GetCookies: true,
			},
			NumCookieSt: 1,
			CookieUpdate: func(cookie *http.Cookie) *http.Cookie {
				return cookie
			},
		},
		{ //7. имитация обновления пары токенов с другого ip адреса
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusOK,
			},
			NumCookieSt: 6,
			CookieUpdate: func(cookie *http.Cookie) *http.Cookie {
				claims := jwt.MapClaims{}
				_, _ = jwt.ParseWithClaims(
					cookie.Value,
					&claims,
					func(token *jwt.Token) (interface{}, error) {
						return []byte(key), nil
					},
				)

				claims["ip"] = "255.255.255.255" //новый ip
				refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
				signedRefreshToken, _ := refreshToken.SignedString([]byte(key))

				return &http.Cookie{
					Name:     cookie.Name,
					Value:    signedRefreshToken,
					HttpOnly: cookie.HttpOnly,
					Path:     cookie.Path,
					Expires:  cookie.Expires,
				}
			},
		},
	}

	for i, testCase := range cases {
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodGet, testCase.Path+testCase.GUID, nil)
		if err != nil {
			t.Fatalf("make request error, num case: [%d], error msg: [%s]", i, err.Error())
		}

		if testCase.CookieUpdate != nil {
			for _, cookie := range cookiesStorage[testCase.NumCookieSt] {
				if cookie.Name == "refresh_token" {
					updatedCookie := testCase.CookieUpdate(cookie)
					req.AddCookie(updatedCookie)
					break
				}
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("get response error, num case: [%d], error msg: [%s]", i, err.Error())
		}
		if resp.StatusCode != testCase.Expected.StatusCode {
			t.Fatalf("unexpected status code: num case: [%d], expected [%d], got [%d]", i, testCase.Expected.StatusCode, resp.StatusCode)
		}

		if testCase.Expected.GetCookies && len(resp.Cookies()) == 0 {
			t.Fatalf("response must have cookie in this num case [%d], but cookies are absent", i)
		}

		if len(resp.Cookies()) != 0 {
			cookiesStorage[i] = resp.Cookies()
		}
	}

}
