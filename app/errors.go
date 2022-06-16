package app

import (
	"jwt-test/models"
	"net/http"
)

var NotFoundHandler = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		res := models.NewResponseStateWithMessage("This resources was not found on our server", nil, false, true)
		res.Respond(w)
		next.ServeHTTP(w, r)
	})
}
