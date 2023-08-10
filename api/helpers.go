package api

import (
	"context"
	"log"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type SignedClaims struct {
	Email     string
	FirstName string
	LastName  string
	UserType  string
	Uid       string
	jwt.RegisteredClaims
}

var SECRET_KEY = "secret"

func GenerateTokens(email, first_name, last_name, user_type, user_id string) (token, refresh_token string) {
	var err error
	claim := &SignedClaims{
		Email:     email,
		FirstName: first_name,
		LastName:  last_name,
		UserType:  user_type,
		Uid:       user_id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	refresh_claim := &SignedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
	}
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Fatal(err)
		return
	}
	refresh_token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refresh_claim).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Fatal(err)
		return
	}
	return token, refresh_token
}

func UpdateToken(token, refresh_token, user_id string) {

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var updateObj primitive.D
	update_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	updateObj = append(updateObj, bson.E{Key: "token", Value: token})
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: refresh_token})
	updateObj = append(updateObj, bson.E{Key: "update_at", Value: update_at})

	upsert := true
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(ctx, bson.M{"user_id": user_id}, bson.M{"$set": updateObj}, &opt)

	if err != nil {
		log.Panic(err)
		return
	}
}

func VerifyPassword(user_password, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(user_password))

	return err == nil
}

func HashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 0)

	return string(hash)
}
