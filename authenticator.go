package authenticator /* import "auth" */

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/brianvoe/sjwt"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/joho/godotenv"
)

type Exception struct {
	Message string `json:"message"`
}

type User struct {
	UserID      primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	ProviderID  string             `json:"providerId" bson:"providerId"`
	Provider    string             `json:"provider" bson:"provider"`
	Name        string             `json:"name" bson:"name"`
	Avatar      string             `json:"avatar" bson:"avatar"`
	Group       string             `json:"group" bson:"group"`
	MemberSince int64              `json:"member_since" bson:"member_since"`
	LastLogin   int64              `json:"last_login" bson:"last_login"`
}

type userKey struct{}

func init() {

	godotenv.Load(".env")

	if len(os.Getenv("JWT_SECRET")) < 10 {
		log.Fatal("No env set")
	}
}

func ExtractUser(req *http.Request) (*User, error) {
	var user *User
	err := mapstructure.Decode(req.Context().Value(&userKey{}), user)

	if err != nil {
		return nil, err
	}

	return user, nil
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

		if next != nil {
			ctx := context.WithValue(req.Context(), &userKey{}, user)
			next(w, req.WithContext(ctx))
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
