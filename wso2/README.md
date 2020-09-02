# WSO2 Auth Package

This package provides several different ways of interacting with WSO2, such as
handling OAuth2 when calling APIs behind WSO2, as well as handling the
Authorization Code grant types.

### Middleware

#### Authorization Code Middleware

This middleware allows you to force users to login when hitting an http endpoint
by utilizing the OAuth2 Authorization Code grant type. 

``` golang
package main

import (
	"net/http"
	
	"https://github.com/byuoitav/auth/wso2"
	"https://github.com/byuoitav/auth/session/cookiestore"
	"https://github.com/labstack/echo"
)

func main() {
	
	// Create WSO2 Client
	client := wso2.New("client_id", "client_secret", "http://gateway:80", "http://localhost:8080")
	
	// Create Session Store
	sessionStore := cookiestore.NewStore()
	
	// Create Echo Router and route group
	router := echo.New()
	authRouter := router.Group("")
	
	// Utilize Auth Code Middleware
	authRouter.Use(echo.WrapMiddleware(client.AuthCodeMiddleware(sessionStore, "default-session")))
	
	authRouter.Get("/hello_world", func(c echo.Context) error{
		c.String(http.StatusOK, "Hello, World!")
	})
	
	router.Start(":8080")
}
```
