package test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var key = "someKey1!"

type AuthTestCase struct {
	GUID     string
	Path     string
	RT       *RefreshToken
	AT       *AccessToken
	Expected Response
}

type RefreshToken struct {
	CookieUpdate func(*http.Cookie) *http.Cookie
	NumCookieSt  int
}

type AccessToken struct {
	TokenUpdate func(string) string
	NumTokenSt  int
}

type Response struct {
	StatusCode int
	GetCookie  bool
	GetBody    bool
}

func TestApp(t *testing.T) {

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
				GetCookie:  true,
				GetBody:    true,
			},
		},
		{ //2. попытка обновить пару токенов, в запросе нет cookie с refresh токеном
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusBadRequest,
			},
		},
		{ //3. попытка обновить пару токенов, в заголовке запроса нет access токена
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusBadRequest,
			},
		},
		{ //4. попытка обновить пару токенов, неправильный refresh токен
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			AT: &AccessToken{
				NumTokenSt: 1,
			},
			RT: &RefreshToken{
				NumCookieSt: 1,
				CookieUpdate: func(cookie *http.Cookie) *http.Cookie {
					return &http.Cookie{
						Name:     cookie.Name,
						Value:    "test",
						HttpOnly: cookie.HttpOnly,
						Path:     cookie.Path,
						Expires:  cookie.Expires,
					}
				},
			},
		},
		{ //5. попытка обновить пару токенов, refresh токен не совпадает с хешем из бд
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			AT: &AccessToken{
				NumTokenSt: 1,
			},
			RT: &RefreshToken{
				NumCookieSt: 1,
				CookieUpdate: func(cookie *http.Cookie) *http.Cookie {

					refreshToken := cookie.Value
					tokenData := strings.Split(refreshToken, ".")
					tokenData[0] = "aaaaaaaaaaaaaaa"

					return &http.Cookie{
						Name:     cookie.Name,
						Value:    strings.Join(tokenData, "."),
						HttpOnly: cookie.HttpOnly,
						Path:     cookie.Path,
						Expires:  cookie.Expires,
					}
				},
			},
		},
		{ //6. попытка обновить пару токенов, неправильный matching key
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			AT: &AccessToken{
				NumTokenSt: 1,
			},
			RT: &RefreshToken{
				NumCookieSt: 1,
				CookieUpdate: func(cookie *http.Cookie) *http.Cookie {

					refreshToken := cookie.Value
					tokenData := strings.Split(refreshToken, ".")
					tokenData[1] = "aaaaa"

					return &http.Cookie{
						Name:     cookie.Name,
						Value:    strings.Join(tokenData, "."),
						HttpOnly: cookie.HttpOnly,
						Path:     cookie.Path,
						Expires:  cookie.Expires,
					}
				},
			},
		},
		{ //7. попытка обновить пару токенов, у access токена изменен payload, т.е. будет ошибка при проверке подписи
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			AT: &AccessToken{
				NumTokenSt: 1,
				TokenUpdate: func(token string) string {
					s := strings.Split(token, ".")
					payload, _ := base64.StdEncoding.DecodeString(s[1])
					newPayload := strings.ReplaceAll(string(payload), "authApp", "unknownApp") //изменение payload
					s[1] = base64.StdEncoding.EncodeToString([]byte(newPayload))

					return strings.Join(s, ".")
				},
			},
			RT: &RefreshToken{
				NumCookieSt: 1,
			},
		},
		{ //8. обновление пары токенов, правильный refresh токен
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusOK,
				GetCookie:  true,
				GetBody:    true,
			},
			AT: &AccessToken{
				NumTokenSt: 1,
			},
			RT: &RefreshToken{
				NumCookieSt: 1,
			},
		},
		{ //9. попытка обновить пару токенов, используя старый refresh токен (полученный в кейсе 1)
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusUnauthorized,
			},
			AT: &AccessToken{
				NumTokenSt: 8,
			},
			RT: &RefreshToken{
				NumCookieSt: 1,
			},
		},
		{ //10. имитация обновления пары токенов с другого ip адреса
			Path: "http://127.0.0.1:8080/api/refresh",
			Expected: Response{
				StatusCode: http.StatusOK,
				GetCookie:  true,
				GetBody:    true,
			},
			AT: &AccessToken{
				NumTokenSt: 8,
				TokenUpdate: func(token string) string {
					claims := jwt.MapClaims{}
					_, _ = jwt.ParseWithClaims(
						token,
						&claims,
						func(token *jwt.Token) (interface{}, error) {
							return []byte(key), nil
						},
					)

					claims["ip"] = "255.255.255.255" //новый ip
					newToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
					signedRefreshToken, _ := newToken.SignedString([]byte(key))

					return signedRefreshToken
				},
			},
			RT: &RefreshToken{
				NumCookieSt: 8,
			},
		},
	}

	cookiesStorage := make(map[int]*http.Cookie)
	accessTokenStorage := make(map[int]string)

	for i, testCase := range cases {
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodGet, testCase.Path+testCase.GUID, nil)
		if err != nil {
			t.Fatalf("make request error, num case: [%d], error msg: [%s]", i, err.Error())
		}

		if testCase.AT != nil {
			accessToken := accessTokenStorage[testCase.AT.NumTokenSt]
			if testCase.AT.TokenUpdate != nil {
				accessToken = testCase.AT.TokenUpdate(accessToken)
			}
			req.Header.Set("access_token", accessToken)
		}

		if testCase.RT != nil {
			cookieWithRefreshToken := cookiesStorage[testCase.RT.NumCookieSt]
			if testCase.RT.CookieUpdate != nil {
				cookieWithRefreshToken = testCase.RT.CookieUpdate(cookieWithRefreshToken)
			}
			req.AddCookie(cookieWithRefreshToken)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("get response error, num case: [%d], error msg: [%s]", i, err.Error())
		}
		if resp.StatusCode != testCase.Expected.StatusCode {
			t.Fatalf("unexpected status code: num case: [%d], expected [%d], got [%d]", i, testCase.Expected.StatusCode, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("body read error, num case: [%d], error msg: [%s]", i, err.Error())
		}

		if testCase.Expected.GetCookie {
			if len(resp.Cookies()) != 1 {
				t.Fatalf("response must have cookie in this num case [%d], but cookies are absent", i)
			} else {
				cookiesStorage[i] = resp.Cookies()[0]
			}
		}

		if testCase.Expected.GetBody {
			if string(body) == "" {
				t.Fatalf("response must have body with access token in this num case [%d], but body is empty", i)
			} else {
				var m map[string]string
				_ = json.Unmarshal(body, &m)
				if token, ok := m["access_token"]; ok {
					accessTokenStorage[i] = token
				}
			}
		}
		resp.Body.Close()
	}

}
