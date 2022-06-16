package app

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"jwt-test/models"
	"log"
	"net/http"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

func Login(login, password string) (res models.ResponseState, isOk bool) {
	account, ok, errRes := models.CheckLoginForm(login, password)
	if !ok {
		return *errRes, false
	}
	tp, atString, rtString, err := models.CreateToken(account.ID)
	if err != nil {
		log.Printf("CreateToken err:\n%v\n", err)
		return models.NewResponseStateWithServerSideError(err), false
	}
	atEncoded := b64.StdEncoding.EncodeToString([]byte(*atString))
	rtEncoded := b64.StdEncoding.EncodeToString([]byte(*rtString))
	log.Printf("atEncoded:\n%v\nrtEncoded:\n%v\natString:\n%v\nrtString:\n%v\n", atEncoded, rtEncoded, *atString, *rtString) //TODO
	saveErr := models.SaveTokenPair(*tp)
	if saveErr != nil {
		log.Printf("SaveTokenPair err:\n%v\n", err)
		return models.NewResponseStateWithServerSideError(err), false
	}
	tokens := map[string]string{
		"access_token":  atEncoded,
		"refresh_token": rtEncoded,
	}

	status := models.NewResponseStateSuccess()
	status.ResData["account"] = account
	status.ResData["tokens"] = tokens
	return status, true
}

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/register", "/login", "/logout", "/token/deleteall", "/token/refresh"} //List of endpoints that doesn't require auth
		requestPath := r.URL.Path                                                                   //current request path

		//check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range notAuth {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		var response models.ResponseState
		tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

		if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
			response = models.NewResponseStateWithMessage("Missing auth token", nil, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}

		splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
		if len(splitted) != 2 {
			response = models.NewResponseStateWithMessage("Invalid/Malformed auth token", nil, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}

		tokenPart := splitted[1] //Grab the token part, what we are truly interested in
		atDecoded, err := b64.StdEncoding.DecodeString(tokenPart)
		if err != nil { //Malformed token, returns with http code 403 as usual
			log.Printf("base64 decoding string err:%v\n", err)
			response = models.NewResponseStateWithMessage("base64 decoding string error", err, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}
		atString := string(atDecoded)

		token, err := jwt.Parse(atString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("ACCESS_SECRET")), nil
		})

		if err != nil { //Malformed token, returns with http code 403 as usual
			log.Printf("jwt.Parse err:%v\n", err)
			log.Printf("tokenPart:\n%v\natDecoded:\n%v\natString:\n%v\n", tokenPart, atDecoded, atString)
			response = models.NewResponseStateWithMessage("Malformed authentication token", err, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}

		// jwt.MapClaims
		var atUserId, atUUID, rtUUID string
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			var ok1, ok2, ok3 bool
			atUserId, ok1 = claims["user_id"].(string)
			atUUID, ok2 = claims["access_uuid"].(string)
			rtUUID, ok3 = claims["refresh_uuid"].(string)
			// for k, v := range claims {
			// 	switch c := v.(type) {
			// 	case string:
			// 		fmt.Printf("Item %q is a string, containing %q\n", k, c)
			// 	default:
			// 		fmt.Printf("Not sure what type item %q is, but I think it might be %T\n", k, c)
			// 	}
			// }
			// log.Printf("%v\n%v %v %v\n", claims, ok1, ok2, ok3)
			if !(ok1 && ok2 && ok3) {
				log.Printf("claims is not valid types err:\n%v\n", err)
				response = models.NewResponseStateWithMessage("token claims is not valid types", err, false, true)
				w.WriteHeader(http.StatusForbidden)
				w.Header().Add("Content-Type", "application/json")
				response.Respond(w)
				return
			}
		} else {
			response = models.NewResponseStateWithMessage("token claims is not valid", nil, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}
		// tmp := uuid.Parse()
		atUserIdDecoded, err := uuid.Parse(atUserId)
		// atUserIdDecoded, err := b64.StdEncoding.DecodeString(atUserId)
		if err != nil { //Malformed token, returns with http code 403 as usual
			// log.Printf("base64 decoding user UUID string err:%v\n", err)
			log.Printf("HEX decoding user UUID string err:%v\n", err)
			response = models.NewResponseStateWithMessage("base64 decoding user UUID string error", err, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}
		atUUIDDecoded, err := uuid.Parse(atUUID)
		// atUUIDDecoded, err := b64.StdEncoding.DecodeString(atUUID)
		if err != nil { //Malformed token, returns with http code 403 as usual
			// log.Printf("base64 decoding access UUID string err:%v\n", err)
			log.Printf("HEX decoding access UUID string err:%v\n", err)
			response = models.NewResponseStateWithMessage("base64 decoding access UUID string error", err, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}
		rtUUIDDecoded, err := uuid.Parse(rtUUID)
		// rtUUIDDecoded, err := b64.StdEncoding.DecodeString(rtUUID)
		if err != nil { //Malformed token, returns with http code 403 as usual
			// log.Printf("base64 decoding refresh UUID string err:%v\n", err)
			log.Printf("HEX decoding refresh UUID string err:%v\n", err)
			response = models.NewResponseStateWithMessage("base64 decoding refresh UUID string error", err, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		}
		// var atUserIdDecoded16, atUUIDDecoded16, rtUUIDDecoded16 [16]byte
		// copy(atUserIdDecoded16[:], atUserIdDecoded)
		// copy(atUUIDDecoded16[:], atUUIDDecoded)
		// copy(rtUUIDDecoded16[:], rtUUIDDecoded)

		acc, err := models.GetDB().ValidAccessToken(uuid.UUID(atUUIDDecoded), uuid.UUID(rtUUIDDecoded), uuid.UUID(atUserIdDecoded))
		// acc, err := models.GetDB().ValidAccessToken(uuid.UUID(atUUIDDecoded16), uuid.UUID(rtUUIDDecoded16), uuid.UUID(atUserIdDecoded16))
		if err != nil {
			log.Printf("jwt.Parse err:%v\n", err)
			log.Printf("Token is not valid err:%v\ntoken.Raw:\n%v\n", err, token.Raw)
			response = models.NewResponseStateWithMessage("Token is not valid.", err, false, true)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			response.Respond(w)
			return
		} else {
			if !token.Valid { //Token is invalid, but in database
				response = models.NewResponseStateWithMessage("Token is not valid, but exist in database. Try to refresh token pair.", err, false, true)
				w.WriteHeader(http.StatusForbidden)
				w.Header().Add("Content-Type", "application/json")
				response.Respond(w)
				return
			}
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		fmt.Println("User logged in %", acc.ID) //Useful for monitoring
		ctx := context.WithValue(r.Context(), "user", acc.ID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	})
}
