package auth

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/brianvoe/sjwt"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/joho/godotenv"
)

type User struct {
	UserID      primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	ProviderID  string             `json:"providerId" bson:"providerId"`
	Provider    string             `json:"provider" bson:"provider"`
	Name        string             `json:"name" bson:"name"`
	Avatar      string             `json:"avatar" bson:"avatar"`
	Group       string             `json:"group" bson:"group"`
	Permissions []string           `json:"permissions" bson:"permissions"`
	MemberSince int64              `json:"member_since" bson:"member_since"`
	LastLogin   int64              `json:"last_login" bson:"last_login"`
}

func (u *User) IsInGroup(groups []string) bool {
	for _, group := range groups {
		if u.Group == group {
			return true
		}
	}
	return false
}

func (u *User) HasPermission(permission string) bool {
	for _, perm := range u.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

func (u *User) HasAnyPermission(permissions []string) bool {
	for _, perm := range permissions {
		if u.HasPermission(perm) {
			return true
		}
	}
	return false
}

type userKey struct{}

type GuardOptions struct {
	Groups      *[]string
	Permissions *[]string
}

func Guard() *GuardOptions {
	return &GuardOptions{}
}

func (g *GuardOptions) G(groups ...string) *GuardOptions {
	g.Groups = &groups
	return g
}

func (g *GuardOptions) P(permissions ...string) *GuardOptions {
	g.Permissions = &permissions
	return g
}

func init() {

	godotenv.Load(".env")

	if len(os.Getenv("JWT_SECRET")) < 10 {
		log.Fatal("No env set")
	}
}

func ExtractUser(req *http.Request) (*User, error) {
	var user User
	err := mapstructure.Decode(req.Context().Value(&userKey{}), &user)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func Middleware(next http.HandlerFunc, opts *GuardOptions) http.HandlerFunc {
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

		if !hasAccessRights(user, opts) {
			unauthorized(w, "Insufficient permissions")
			return
		}

		if next != nil {
			ctx := context.WithValue(req.Context(), &userKey{}, user)
			next(w, req.WithContext(ctx))
		}
	})
}

func hasAccessRights(user User, opts *GuardOptions) bool {
	if opts != nil {
		groupCond := opts.Groups != nil && user.IsInGroup(*opts.Groups)
		permsCond := opts.Permissions != nil && user.HasAnyPermission(*opts.Permissions)

		return groupCond || permsCond
	}
	return true
}

func unauthorized(w http.ResponseWriter, reason string) {
	http.Error(w, reason, http.StatusUnauthorized)
}
