package utils

import (
	"encoding/json"
	"net/http"
)

func Message(is_ok bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": is_ok, "message": message}
}

func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
