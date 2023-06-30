package internal

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func NewRouter() *gin.Engine {
	gin.SetMode(gin.DebugMode)

	r := gin.New()
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	r.Use(cors.New(config))
	v1 := r.Group("api/v1")

	// Alive check
	v1.GET("/", HealthHandler)

	v1.POST("/bind-user-p2", BindUserAndP2)

	v1.POST("/get-address", GetAddressMessageHandler)

	v1.POST("/init-p2-content", InitP2ContentHandler)

	v1.POST("/p2-step1", P2Step1Handler)

	v1.POST("/p2-step2", P2Step2Handler)

	return r
}
