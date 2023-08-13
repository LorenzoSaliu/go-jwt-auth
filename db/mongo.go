package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewConnection() *mongo.Client {
	// TODO: Add mongoDB connection string to .env file

	ctx, cancel := context.WithTimeout(context.TODO(), 20*time.Second)
	defer cancel()
	url := "mongodb://127.0.0.1:27017/auth" //TODO make sure this is it

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(url))
	if err != nil {
		log.Panic(err.Error())
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB")
	return client
}

var DB *mongo.Client = NewConnection()

func Close() {
	DB.Disconnect(context.TODO())
}

func GetCollection(collectionName string) *mongo.Collection {
	return (DB.Database("auth").Collection(collectionName))
}
