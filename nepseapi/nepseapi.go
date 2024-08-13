package main

import (
	"log"

	"github.com/ravilmc/nepsetools/nepseapi/jwtutils"
)

func main() {
	authenticateResponse, err := jwtutils.Authenticate()
	if err != nil {
		panic(err)
	}

	accessToken, err := authenticateResponse.GetParsedAccessToken()
	if err != nil {
		panic(err)
	}

	log.Println("Access Token: ", accessToken)

}
