package main

import "go.mongodb.org/mongo-driver/bson/primitive"

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
