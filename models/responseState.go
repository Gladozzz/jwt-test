package models

import (
	"encoding/json"
	"net/http"
)

type ResponseState struct {
	ResData     map[string]interface{}
	ServerError error
	IsOk        bool
}

func NewResponseState(ServerError error, IsOk bool) ResponseState {
	return ResponseState{map[string]interface{}{}, ServerError, IsOk}
}

func NewResponseStateWithData(ResData map[string]interface{}, ServerError error, IsOk bool) ResponseState {
	return ResponseState{map[string]interface{}{}, ServerError, IsOk}
}

func NewResponseStateWithMessage(msg string, ServerError error, ClientIsOk bool, ServerIsOk bool) ResponseState {
	return ResponseState{map[string]interface{}{"message": msg, "isOk": ClientIsOk}, ServerError, ServerIsOk}
}

func NewResponseStateSuccess() ResponseState {
	return ResponseState{map[string]interface{}{"message": "success", "isOk": true}, nil, true}
}

func NewResponseStateWithServerSideError(ServerError error) ResponseState {
	return ResponseState{map[string]interface{}{"message": "error on server side", "isOk": false}, ServerError, false}
}

func (resState *ResponseState) Respond(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resState.ResData)
}
