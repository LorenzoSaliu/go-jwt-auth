package main

import (
	"net/http"
	"os"

	"github.com/LorenzoSaliu/jwt-auth/api"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	app := fiber.New()
	app.Use(logger.New()) // Logger middleware

	app.Get("/auth/v1/health-check", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).JSON(fiber.Map{"message": "server is up and running"})
	})

	v1 := app.Group("/auth/v1")

	v1.Post("/signin", api.SignInHandler)
	v1.Get("/login", api.LogInHandler)
	v1.Get("/user", api.GetUsersHandler)
	v1.Get("/user/:id", api.GetUserHandler)

	//get port
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	//start server
	app.Listen(":" + port)

}
