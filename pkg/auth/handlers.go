package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	Storage
	EmailSender
	Keys *Keys
}

type Keys struct {
	Access  string
	Refresh string
}

func NewKeys() *Keys {
	return &Keys{
		Access:  "someKey1!",
		Refresh: "anotherKey123!*",
	}
}

type Storage interface {
	CheckGUID(guid string) (int, error)
	AddNewRefreshID(id int, refreshID []byte) error
	GetHashedRefreshID(id int) ([]byte, error)
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

	//создание cookie с access токеном
	cookieWithAccessToken, err := createCookieWithAccessToken(id, r.RemoteAddr, ah.Keys.Access)
	if err != nil {
		log.Printf("sign access token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//создание cookie с refresh токеном
	refreshID := uuid.New()
	cookieWithRefreshToken, err := createCookieWithRefreshToken(id, r.RemoteAddr, ah.Keys.Refresh, refreshID.String())
	if err != nil {
		log.Printf("sign refresh token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//добавление сформированного refreshID в базу к id пользователя
	hashedID, err := bcrypt.GenerateFromPassword([]byte(refreshID.String()), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("error with generate bcrypt hash: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = ah.Storage.AddNewRefreshID(id, hashedID)
	if err != nil {
		log.Printf("error with add new hashed refresh id: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookieWithAccessToken)
	http.SetCookie(w, cookieWithRefreshToken)
	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	refreshTokenFromReq := cookie.Value

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(
		refreshTokenFromReq,
		&claims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(ah.Keys.Refresh), nil
		},
	)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshID := claims["refresh_id"].(string)

	id := int(claims["user_id"].(float64))
	hashedID, err := ah.Storage.GetHashedRefreshID(id)
	if err != nil {
		log.Printf("check refresh id error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(hashedID, []byte(refreshID))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//отправление warning письма юзеру о доступе к его данным с другого устройства
	if r.RemoteAddr != claims["ip"] {
		msg := fmt.Sprintf("WARNING, somebody get access to your data\nip: [%s]\nuser-agent: [%s]\nIf this is you, ignore this message\n", r.RemoteAddr, r.UserAgent())
		email := "some email"
		err := ah.EmailSender.Send(email, msg)
		if err != nil {
			log.Printf("send warning message error: [%s], refresh operation stopped\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			log.Printf("warning msg succesfully sended to [%s]\n", email)
		}
		log.Printf("unknown ip get access to refresh operation: unknown ip: [%s], expected ip: [%s], refresh id: [%s]\n", r.RemoteAddr, claims["ip"], claims["refresh_id"])
	}

	//создание новой cookie с новым access токеном
	cookieWithAccessToken, err := createCookieWithAccessToken(id, r.RemoteAddr, ah.Keys.Access)
	if err != nil {
		log.Printf("sign access token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//создание новой cookie с новым refresh токеном
	newRefreshID := uuid.New()

	cookieWithRefreshToken, err := createCookieWithRefreshToken(id, r.RemoteAddr, ah.Keys.Refresh, newRefreshID.String())
	if err != nil {
		log.Printf("sign refresh token error: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//добавление сформированного newRefreshID в базу к id пользователя
	newHashedID, err := bcrypt.GenerateFromPassword([]byte(newRefreshID.String()), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("error with generate bcrypt hash: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = ah.Storage.AddNewRefreshID(id, newHashedID)
	if err != nil {
		log.Printf("error with add new hashed refresh id: [%s]\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookieWithAccessToken)
	http.SetCookie(w, cookieWithRefreshToken)
	w.WriteHeader(http.StatusOK)

}
