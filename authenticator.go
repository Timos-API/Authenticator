package authenticator

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/brianvoe/sjwt"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"

	"github.com/joho/godotenv"
)

func init() {
	if err := godotenv.Load(".env"); err == nil {
		return
	}

	if len(os.Getenv("JWT_SECRET")) < 10 {
		log.Fatal("No env set")
	}
}

func ExtractUser(req *http.Request) User {
	var user User
	mapstructure.Decode(context.Get(req, "user"), &user)
	return user
}

func AuthMiddleware(next http.HandlerFunc, groups []string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			unauthorized(w, "No authorization header set")
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			unauthorized(w, "No bearer token set")
			return
		}

		jwt := bearerToken[1]
		verified := sjwt.Verify(jwt, []byte(os.Getenv("JWT_SECRET")))

		if !verified {
			unauthorized(w, "Invalid JWT")
			return
		}

		claims, err := sjwt.Parse(jwt)
		if err == nil {
			err = claims.Validate()
		}

		if err != nil {
			unauthorized(w, err.Error())
			return
		}

		var user User
		claims.ToStruct(&user)

		if groups != nil && !contains(groups, user.Group) {
			unauthorized(w, "Insufficient permissions")
			return
		}

		context.Set(req, "user", user)

		if next != nil {
			next(w, req)
		}
	})
}

func unauthorized(w http.ResponseWriter, reason string) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Add("content-type", "application/json")
	json.NewEncoder(w).Encode(Exception{reason})
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
