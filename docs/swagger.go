package docs

import "github.com/swaggo/swag"

// @title StorX Monitor API
// @version 1.0
// @description API documentation for StorX Monitor server
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:10100
// @BasePath /api/v0

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name _tokenKey

// @tag.name auth
// @tag.description Authentication operations

// @tag.name projects
// @tag.description Project management operations

// @tag.name buckets
// @tag.description Bucket management operations

// @tag.name api-keys
// @tag.description API key management operations

// @tag.name payments
// @tag.description Payment and billing operations

// @tag.name analytics
// @tag.description Analytics operations

func SwaggerInfo() {
	swag.Register(swag.Name, &swag.Spec{
		InfoInstanceName: "swagger",
		SwaggerTemplate:  docTemplate,
	})
}

// This will be populated by swag init
var docTemplate = ``
