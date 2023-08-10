package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id" json:"id"`
	UserType     string             `json:"user_type" validate:"required,oneof=ADMIN USER"`
	UserID       string             `json:"user_id"`
	Password     string             `json:"password" validate:"required,min=6"`
	FirstName    string             `json:"firs_name" validate:"required,min=2,max=255"`
	LastName     string             `json:"last_name" validate:"required,min=2,max=255"`
	Email        string             `json:"email" validate:"required,email"`
	Phone        string             `json:"phone" validate:"required,e164"`
	Token        string             `json:"token"`
	RefreshToken string             `json:"refresh_token"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
}
