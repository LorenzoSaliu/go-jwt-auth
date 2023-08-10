package models

import "time"

type Meta struct {
	Status        int       `json:"status"`
	Message       string    `json:"message"`
	TimeStamp     time.Time `json:"time_stamp"`
	CorrelationId string    `json:"correlation_id"`
}

type SuccessResponse struct {
	Meta   Meta        `json:"meta"`
	Result interface{} `json:"result"`
}

type ErrorResponse struct {
	Meta   Meta        `json:"meta"`
	Errors interface{} `json:"errors"`
}
