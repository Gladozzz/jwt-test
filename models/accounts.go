package models

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	LoginRequiredMsg        = "Wrong credentials, login is required"
	PasswordRequiredMsg     = "Wrong credentials, password is required"
	PasswordIsNotInRulesMsg = "Wrong credentials, password is must be more than 6 characters"
	PasswordsNotMatchMsg    = "Wrong credentials, passwords is not match"
	LoginAlreadyInUseMsg    = "Wrong credentials, login is already in use"
	RefreshTokenMsg         = "Wrong HashedRefreshToken"
	WrongAccessTokenMsg     = "Wrong AccessToken"
	AccountCredentialsMsg   = "Wrong account credentials"
)

type TokenPair struct {
	UserId             uuid.UUID
	AccessUuid         uuid.UUID
	RefreshUuid        uuid.UUID
	HashedRefreshToken []byte
	RefreshToken       string
	AtExpires          int64
	RtExpires          int64
}

//model for db and parsing requests
type TokenForm struct {
	AccessToken  string
	RefreshToken string
}

//model for db and parsing requests
type LoginForm struct {
	Login    string
	Password string
}

//a struct to rep user account
type Account struct {
	ID       uuid.UUID
	Login    string
	Password string
	Tokens   []TokenPair
}

func CreateToken(userId uuid.UUID) (tokenPair *TokenPair, accessToken *string, refreshToken *string, err error) {
	tp := &TokenPair{}
	tp.UserId = userId
	tp.AtExpires = time.Now().Add(time.Hour * 24).Unix()
	tp.AccessUuid = uuid.New()

	tp.RtExpires = time.Now().Add(time.Hour * 24 * 30).Unix()
	tp.RefreshUuid = uuid.New()
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = tp.AccessUuid.String()
	atClaims["user_id"] = tp.UserId.String()
	atClaims["exp"] = tp.AtExpires
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = tp.RefreshUuid.String()
	atClaims["refresh_uuid"] = tp.RefreshUuid.String()
	rtClaims["access_uuid"] = tp.AccessUuid.String()
	rtClaims["user_id"] = tp.UserId.String()
	rtClaims["exp"] = tp.RtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	atString, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		log.Printf("CreateToken err on signing atString: %v\n", err)
		return nil, nil, nil, err
	}
	rtClaims["access_token"] = atString
	rt := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)
	rtString, err := rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		log.Printf("CreateToken err on signing rtString: %v\n", err)
		return nil, nil, nil, err
	}
	rtBytes, err := bcrypt.GenerateFromPassword([]byte(rtString), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("CreateToken err on hashing rtString: %v\n", err)
		return nil, nil, nil, err
	}
	tp.HashedRefreshToken = rtBytes
	tp.RefreshToken = rtString
	return tp, &atString, &rtString, nil
}

//Validate incoming user details...
func (lf *LoginForm) Validate() (res *ResponseState, isOk bool) {
	var status *ResponseState = nil
	if len(lf.Login) < 4 {
		tmp := NewResponseStateWithMessage(LoginRequiredMsg, nil, false, true)
		status = &tmp
		return status, false
	}

	if lf.Password == "" {
		tmp := NewResponseStateWithMessage(PasswordRequiredMsg, nil, false, true)
		status = &tmp
		return status, false
	}

	if len(lf.Password) < 6 {
		tmp := NewResponseStateWithMessage(PasswordIsNotInRulesMsg, nil, false, true)
		status = &tmp
		return status, false
	}

	//Login must be unique
	sameLoginAcc, err := GetDB().getAccountByLogin(lf.Login)
	if err != nil && err.Error() != "mongo: no documents in result" {
		log.Printf("Validate err in getAccountByLogin: %v\n", err)
		tmp := NewResponseStateWithServerSideError(err)
		status = &tmp
		return status, false
	}
	if sameLoginAcc != nil {
		tmp := NewResponseStateWithMessage(LoginAlreadyInUseMsg, nil, false, true)
		status = &tmp
		return status, false
	}

	return nil, true
}

func Register(lf *LoginForm) (resState ResponseState, isOk bool) {
	if rs, ok := lf.Validate(); !ok {
		return *rs, ok
	}

	var account = Account{}
	account.Login = lf.Login
	//Create GUID
	account.ID = uuid.New()
	account.Tokens = []TokenPair{}

	//Hashing password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(lf.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("CreateToken err on hashing rtString: %v\n", err)
		return NewResponseStateWithServerSideError(err), false
	}
	account.Password = string(hashedPassword)

	//Create TokenPair
	tp, atString, rtString, err := CreateToken(account.ID)
	if err != nil {
		return NewResponseStateWithServerSideError(err), false
	} else {
		account.Tokens = append(account.Tokens, *tp)
	}

	//Put new account to DB
	if err = GetDB().putAccount(account); err != nil {
		log.Printf("CreateToken err on put account to db: %v\n", err)
		return NewResponseStateWithServerSideError(err), false
	}

	account.Password = "" //delete password
	lf.Password = ""
	account.Tokens = []TokenPair{}

	atEncoded := b64.StdEncoding.EncodeToString([]byte(*atString))
	rtEncoded := b64.StdEncoding.EncodeToString([]byte(*rtString))
	tokens := map[string]string{
		"access_token":  atEncoded,
		"refresh_token": rtEncoded,
	}
	status := NewResponseStateSuccess()
	status.ResData["account"] = account
	status.ResData["tokens"] = tokens
	return status, true
}

func CheckLoginForm(login, password string) (acc *Account, isOk bool, errResponse *ResponseState) {
	var errRes *ResponseState = nil
	account, err := GetDB().getAccountByLogin(login)
	if err != nil {
		log.Printf("CheckLoginForm err in getAccountByLogin: %v\n", err)
		tmp := NewResponseStateWithServerSideError(err)
		errRes = &tmp
		return nil, false, errRes
	}
	account.Tokens = nil

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		log.Printf("CheckLoginForm err in bcrypt.CompareHashAndPassword: %v\n", err)
		tmp := NewResponseStateWithServerSideError(err)
		errRes = &tmp
		return nil, false, errRes
	}
	account.Password = ""
	return account, true, nil
}

func RefreshTokenPair(rt string) (resState ResponseState, isOk bool) {
	rtDecoded, err := b64.StdEncoding.DecodeString(rt)
	if err != nil {
		log.Printf("RefreshTokenPair err in DecodeString: %v\n", err)
		return NewResponseStateWithMessage("base64 decoding string error", err, false, true), false
	}
	log.Printf("string(rtDecoded) %v", string(rtDecoded))
	newAT, newRT, err := GetDB().refreshTokenPair(rtDecoded)
	if err != nil {
		log.Printf("RefreshTokenPair err in GetDB().refreshTokenPair: %v\n", err)
		return NewResponseStateWithServerSideError(err), false
	}
	atEncoded := b64.StdEncoding.EncodeToString([]byte(*newAT))
	rtEncoded := b64.StdEncoding.EncodeToString([]byte(*newRT))
	tokens := map[string]string{
		"access_token":  atEncoded,
		"refresh_token": rtEncoded,
	}
	status := NewResponseStateSuccess()
	status.ResData["tokens"] = tokens
	return status, true
}

func DeleteTokenPair(at string) (resState ResponseState, isOk bool) {
	atDecoded, err := b64.StdEncoding.DecodeString(at)
	if err != nil {
		log.Printf("DeleteTokenPair err in DecodeString: %v\n", err)
		return NewResponseStateWithMessage("base64 decoding string error", err, false, true), true
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
		log.Printf("DeleteTokenPair jwt.Parse err:%v\n", err)
		return NewResponseStateWithMessage("Malformed authentication token", err, false, true), false
	}

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
			return NewResponseStateWithMessage("token claims is not valid types", err, false, true), false
		}
	} else {
		log.Printf("claims is not valid types err:\n%v\n", err)
		return NewResponseStateWithMessage("token claims is not valid", nil, false, true), false
	}
	atUserIdDecoded, err := uuid.Parse(atUserId)
	if err != nil {
		log.Printf("HEX decoding user UUID string err:%v\n", err)
		return NewResponseStateWithMessage("base64 decoding user UUID string error", err, false, true), false
	}
	atUUIDDecoded, err := uuid.Parse(atUUID)
	if err != nil {
		log.Printf("HEX decoding access UUID string err:%v\n", err)
		return NewResponseStateWithMessage("base64 decoding access UUID string error", err, false, true), false
	}
	rtUUIDDecoded, err := uuid.Parse(rtUUID)
	if err != nil {
		log.Printf("HEX decoding refresh UUID string err:%v\n", err)
		return NewResponseStateWithMessage("base64 decoding refresh UUID string error", err, false, true), false
	}

	err = GetDB().RemoveTokenFromAccount(atUserIdDecoded, atUUIDDecoded, rtUUIDDecoded)
	if err != nil {
		return NewResponseStateWithMessage(WrongAccessTokenMsg, err, false, true), true
	}
	return NewResponseStateSuccess(), true
}

func DeleteAllTokenPairsOfUser(lf LoginForm) (resState ResponseState, isOk bool) {
	err := GetDB().deleteAllTokensFromAccount(lf)
	if err != nil {
		log.Printf("DeleteAllTokenPairsOfUser err: %v\n", err)
		return NewResponseStateWithMessage(WrongAccessTokenMsg, err, false, false), false
	}
	return NewResponseStateSuccess(), true
}

func SaveTokenPair(tp TokenPair) error {
	err := GetDB().addTokenToAccount(tp)
	if err != nil {
		return err
	}
	return nil
}
