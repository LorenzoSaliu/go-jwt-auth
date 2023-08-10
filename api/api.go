package api

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/LorenzoSaliu/jwt-auth/db"
	"github.com/LorenzoSaliu/jwt-auth/models"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = db.GetCollection("users")
var validate = validator.New()

func GetUsersHandler(c *fiber.Ctx) error {
	var checkToken models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := c.GetReqHeaders()["Token"]
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusNotFound,
				Message:       "Unauthorized",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": "Unauthorized"}})
	}

	err := userCollection.FindOne(ctx, bson.M{"token": token}).Decode(&checkToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusNotFound,
					Message:       "no data found",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": err.Error()}})
		}
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusInternalServerError,
				Message:       "error finding data process",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": err.Error()}})
	}

	if checkToken.UserType == "ADMIN" {

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err := strconv.Atoi(c.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}
		startIndex, err := strconv.Atoi(c.Query("startIndex"))
		if err != nil || startIndex < 1 {
			startIndex = (page - 1) * recordPerPage
		}

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
		}}}
		projectStage := bson.D{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"data", startIndex, recordPerPage}}}},
		}}}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage,
			groupStage,
			projectStage,
		})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusInternalServerError,
					Message:       "error finding data process",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": err.Error()}})
		}

		var users []bson.M
		if err := result.All(ctx, &users); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusInternalServerError,
					Message:       "error finding data process",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": err.Error()}})
		}

		return c.Status(http.StatusOK).JSON(models.SuccessResponse{
			Meta: models.Meta{
				Status:        http.StatusOK,
				Message:       "OK",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Result: users})

	}

	return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{
		Meta: models.Meta{
			Status:        http.StatusUnauthorized,
			Message:       "Unauthorized",
			TimeStamp:     time.Now(),
			CorrelationId: "X-Correlation-Id"},
		Errors: &fiber.Map{"data": "Unauthorized"}})
}

func GetUserHandler(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result models.User
	token := c.GetReqHeaders()["Token"]
	objID, err := primitive.ObjectIDFromHex(c.Params("id"))
	if err != nil {
		panic(err)
	}

	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusNotFound,
					Message:       "no data found",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": err.Error()}})
		}
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusInternalServerError,
				Message:       "error finding data process",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": err.Error()}})
	}

	if result.UserType == "USER" && result.Token == token {
		return c.Status(http.StatusOK).JSON(models.SuccessResponse{
			Meta: models.Meta{
				Status:        http.StatusOK,
				Message:       "OK",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Result: result})
	}
	if result.UserType == "ADMIN" {
		return c.Status(http.StatusOK).JSON(models.SuccessResponse{
			Meta: models.Meta{
				Status:        http.StatusOK,
				Message:       "OK",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Result: result})
	}
	return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{
		Meta: models.Meta{
			Status:        http.StatusUnauthorized,
			Message:       "Unauthorized",
			TimeStamp:     time.Now(),
			CorrelationId: "X-Correlation-Id"},
		Errors: &fiber.Map{"data": "Unauthorized"}})
}

func SignInHandler(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user models.User
	var err error
	defer cancel()

	//validate the request body structure
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusBadRequest,
				Message:       "Body Parser Error",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": err.Error()}})
	}

	//use the validator library to validate required fields
	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusBadRequest,
				Message:       "Validation Error",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": validationErr.Error()}})
	}

	{ //Check if the user already exists
		//Check id
		count, err := userCollection.CountDocuments(ctx, bson.M{"userid": user.UserID})
		defer cancel()
		if err != nil {
			log.Panicln(err)
			return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusInternalServerError,
					Message:       "Check UserID Error",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "Error while checking userID"}})
		}
		if count > 0 {
			return c.Status(http.StatusConflict).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusConflict,
					Message:       "User already exists",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "User already exists"}})
		}
		//Check email
		count, err = userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panicln(err)
			return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusInternalServerError,
					Message:       "Check Email Error",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "Error while checking email"}})
		}
		if count > 0 {
			return c.Status(http.StatusConflict).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusConflict,
					Message:       "User already exists",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "User already exists"}})
		}
		//Check phone
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Panicln(err)
			return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusInternalServerError,
					Message:       "Check Phone Error",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "Error while checking phone"}})
		}
		if count > 0 {
			return c.Status(http.StatusConflict).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusConflict,
					Message:       "User already exists",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "User already exists"}})
		}
	}

	//insert the new user field
	user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()
	user.Password = HashPassword(user.Password)
	log.Println("p: ", user.Password)
	user.Token, user.RefreshToken = GenerateTokens(user.Email, user.FirstName, user.LastName, user.UserType, user.UserID)

	result, err := userCollection.InsertOne(ctx, user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusBadRequest,
				Message:       "DB Insert Error",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": err.Error()}})
	}

	return c.Status(http.StatusCreated).JSON(models.SuccessResponse{
		Meta: models.Meta{
			Status:        http.StatusOK,
			Message:       "Insert Success",
			TimeStamp:     time.Now(),
			CorrelationId: "X-Correlation-Id"},
		Result: &fiber.Map{"newID": result.InsertedID}})
}

func LogInHandler(c *fiber.Ctx) error {
	var result models.User
	var err error
	uid := c.Query("user_id")
	password := c.Query("password")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = userCollection.FindOne(ctx, bson.M{"userid": uid}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(models.ErrorResponse{
				Meta: models.Meta{
					Status:        http.StatusNotFound,
					Message:       "no data found",
					TimeStamp:     time.Now(),
					CorrelationId: "X-Correlation-Id"},
				Errors: &fiber.Map{"data": "User not found"}})
		}
		return c.Status(http.StatusInternalServerError).JSON(models.ErrorResponse{
			Meta: models.Meta{
				Status:        http.StatusInternalServerError,
				Message:       "error finding data process",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Errors: &fiber.Map{"data": err.Error()}})
	}

	if VerifyPassword(password, result.Password) {

		token, refresh_token := GenerateTokens(result.Email, result.FirstName, result.LastName, result.UserType, result.UserID)
		UpdateToken(token, refresh_token, result.UserID)

		return c.Status(http.StatusOK).JSON(models.SuccessResponse{
			Meta: models.Meta{
				Status:        http.StatusOK,
				Message:       "OK",
				TimeStamp:     time.Now(),
				CorrelationId: "X-Correlation-Id"},
			Result: &fiber.Map{"data": &fiber.Map{"token": result.Token, "id": result.ID}}})
	}

	return c.Status(http.StatusUnauthorized).JSON(models.ErrorResponse{
		Meta: models.Meta{
			Status:        http.StatusNotFound,
			Message:       "Authentication Failed",
			TimeStamp:     time.Now(),
			CorrelationId: "X-Correlation-Id"},
		Errors: &fiber.Map{"data": "Authentication Failed: ID or Password is incorrect"}})

}
