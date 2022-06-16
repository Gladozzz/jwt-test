package controllers

import (
	"encoding/json"
	"fmt"
	"jwt-test/app"
	"jwt-test/models"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

func newResponseStateInvalidRequest(err error) models.ResponseState {
	return models.NewResponseStateWithMessage("invalid request", err, false, true)
}

func newResponseStateInvalidRequestRef(err error) *models.ResponseState {
	tmp := newResponseStateInvalidRequest(err)
	return &tmp
}

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

var SayHi = func(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Hi")
	resp := models.NewResponseStateWithMessage("Hi!", nil, true, true)
	resp.Respond(w)
}

var CreateAccount = func(w http.ResponseWriter, r *http.Request) {

	lf := &models.LoginForm{}
	fmt.Println("CreateAccount")
	err := json.NewDecoder(r.Body).Decode(lf) //decode the request body into struct and failed if any error occur
	if err != nil {
		log.Printf("CreateAccount err on decoding json:\n%v\njson:%v\nlf:\n%v", err, r.Body, lf)
		status := newResponseStateInvalidRequest(err)
		status.Respond(w)
		return
	}

	resp, _ := models.Register(lf) //Create account
	resp.Respond(w)
}

var AuthenticateWithLogin = func(w http.ResponseWriter, r *http.Request) {

	lf := &models.LoginForm{}
	fmt.Println("AuthenticateWithLogin")
	err := json.NewDecoder(r.Body).Decode(lf) //decode the request body into struct and failed if any error occur
	if err != nil {
		status := newResponseStateInvalidRequest(err)
		status.Respond(w)
		return
	}
	resp, _ := app.Login(lf.Login, lf.Password)
	resp.Respond(w)
}

type RefreshTokenForm struct {
	RefreshToken string `json:"refresh_token"`
}

var RefreshAuth = func(w http.ResponseWriter, r *http.Request) {

	rtf := &RefreshTokenForm{}                 // This refresh token is base64 encoded
	err := json.NewDecoder(r.Body).Decode(rtf) //decode the request body into struct and failed if any error occur
	if err != nil {
		status := newResponseStateInvalidRequest(err)
		status.Respond(w)
		return
	}
	// rtDecoded, err := b64.StdEncoding.DecodeString(rtf.RefreshToken)
	// if err != nil {
	// 	log.Printf("RefreshAuth err in DecodeString:\n%v\n", err)
	// 	status := models.NewResponseStateWithMessage("base64 decoding string error", err, false, true)
	// 	status.Respond(w)
	// }
	// resp, _ := models.RefreshTokenPair(string(rtDecoded))
	resp, _ := models.RefreshTokenPair(rtf.RefreshToken)
	resp.Respond(w)
}

type AccessTokenForm struct {
	AccessToken string `json:"access_token"`
}

var Logout = func(w http.ResponseWriter, r *http.Request) {

	atf := &AccessTokenForm{}
	err := json.NewDecoder(r.Body).Decode(atf) //decode the request body into struct and failed if any error occur
	if err != nil {
		status := newResponseStateInvalidRequest(err)
		status.Respond(w)
		return
	}
	resp, _ := models.DeleteTokenPair(atf.AccessToken)
	resp.Respond(w)
}

var DeleteAllTokensOfUser = func(w http.ResponseWriter, r *http.Request) {

	lf := &models.LoginForm{}
	err := json.NewDecoder(r.Body).Decode(lf) //decode the request body into struct and failed if any error occur
	if err != nil {
		status := newResponseStateInvalidRequest(err)
		status.Respond(w)
		return
	}
	_, ok, errRes := models.CheckLoginForm(lf.Login, lf.Password)
	if !ok {
		errRes.Respond(w)
		return
	}
	resp, _ := models.DeleteAllTokenPairsOfUser(*lf)
	resp.Respond(w)
}
