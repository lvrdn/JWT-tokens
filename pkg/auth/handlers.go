package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	AccessKey        string
	AccessExpMinutes int
	RefreshExpMonths int
	Storage
	EmailSender
}

type Storage interface {
	CheckGUID(guid string) (int, error)
	AddNewRefreshToken(id int, refreshID []byte, expDate time.Time) error
	GetHashedRefreshTokenAndExpDate(id int) ([]byte, *time.Time, error)
}

type EmailSender interface {
	Send(addr, text string) error
}

type Resp map[string]interface{}

func (ah *AuthHandler) Issue(w http.ResponseWriter, r *http.Request) {
	guid := r.FormValue("guid")
	if guid == "" {
		response := Resp{"error": "request must have query param `guid`"}
		responseData, err := json.Marshal(response)
		if err != nil {
			log.Printf("error with marshal reponse: reponse [%v], error [%s]\n", response, err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(responseData)
		return
	}

	id, err := ah.Storage.CheckGUID(guid)
	if err != nil {
		if err == sql.ErrNoRows {
			response := Resp{"error": "unknown value of query param `guid`"}
			responseData, err := json.Marshal(response)
			if err != nil {
				log.Printf("error with marshal reponse: reponse [%v], error [%s]\n", response, err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Write(responseData)
			return
		}
		log.Printf("db check query error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//создание refresh токена
	refreshToken, matchingKey := newRefreshToken()

	//добавление сформированного refresh token в базу
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("error with generate bcrypt hash: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	expDate := time.Now().AddDate(0, ah.RefreshExpMonths, 0)
	err = ah.Storage.AddNewRefreshToken(id, hashedRefreshToken, expDate)
	if err != nil {
		log.Printf("error with add new hashed refresh token to db: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//создание подписанного access токена
	signedAccessToken, err := createSignedAccessToken(id, ah.AccessExpMinutes, r.RemoteAddr, ah.AccessKey, matchingKey)
	if err != nil {
		log.Printf("create signed access token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Path:     "/api/refresh",
		Expires:  expDate,
	})

	response := Resp{"access_token": signedAccessToken}
	responseData, err := json.Marshal(response)
	if err != nil {
		log.Printf("error with marshal reponse with access token: reponse [%v], error [%s]\n", response, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(responseData)
}

func (ah *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("refresh_token")
	accessTokenFromReq := r.Header.Get("access_token")

	if err != nil || accessTokenFromReq == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	refreshTokenFromReq := cookie.Value

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(
		accessTokenFromReq,
		&claims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(ah.AccessKey), nil
		},
	)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//получение нужных значений из claims
	matchingKey := claims["matching_key"].(string)
	id := int(claims["user_id"].(float64))
	ip := claims["ip"].(string)

	//проверка на наличие самого токена и matching key в полученном refresh токене
	refreshTokenValues := strings.Split(refreshTokenFromReq, ".")
	if len(refreshTokenValues) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//проверка на соответствие refresh и access токенов
	if refreshTokenValues[1] != matchingKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hashedRefreshToken, expDate, err := ah.Storage.GetHashedRefreshTokenAndExpDate(id)
	if err != nil {
		log.Printf("get hashad refresh token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//проверка срока жизни refresh токена
	if !time.Now().Before(*expDate) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//проверка на соответствие refresh токена из запроса и из базы
	err = bcrypt.CompareHashAndPassword(hashedRefreshToken, []byte(refreshTokenFromReq))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//отправление warning письма юзеру о доступе к его данным с другого устройства
	if r.RemoteAddr != ip {
		msg := fmt.Sprintf("WARNING, somebody get access to your data\nip: [%s]\nuser-agent: [%s]\nIf this is you, ignore this message\n", r.RemoteAddr, r.UserAgent())
		email := "some email"
		err := ah.EmailSender.Send(email, msg)
		if err != nil {
			log.Printf("send warning message error: [%s], refresh operation stopped\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			log.Printf("warning message succesfully sended to [%s]\n", email)
		}
		log.Printf("unknown ip get access to refresh operation: unknown ip: [%s], expected ip: [%s], refresh id: [%s]\n", r.RemoteAddr, ip, refreshTokenFromReq)
	}

	//создание refresh токена
	refreshToken, matchingKey := newRefreshToken()

	//добавление сформированного refresh token в базу
	hashedRefreshToken, err = bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("error with generate bcrypt hash: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newExpDate := time.Now().AddDate(0, ah.RefreshExpMonths, 0)
	err = ah.Storage.AddNewRefreshToken(id, hashedRefreshToken, newExpDate)
	if err != nil {
		log.Printf("error with add new hashed refresh token to db: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//создание подписанного access токена
	signedAccessToken, err := createSignedAccessToken(id, ah.AccessExpMinutes, r.RemoteAddr, ah.AccessKey, matchingKey)
	if err != nil {
		log.Printf("create signed access token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Path:     "/api/refresh",
		Expires:  newExpDate,
	})

	response := Resp{"access_token": signedAccessToken}
	responseData, err := json.Marshal(response)
	if err != nil {
		log.Printf("error with marshal reponse with access token: reponse [%v], error [%s]\n", response, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(responseData)

}
