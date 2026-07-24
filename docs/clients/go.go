// Go — библиотека: github.com/pquerna/otp (`go get github.com/pquerna/otp`)
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	secret := os.Getenv("AUTH_TOTP_SECRET") // base32
	service := os.Getenv("JWT_SERVICE_URL")
	if service == "" {
		service = "http://localhost:8080"
	}

	code, _ := totp.GenerateCode(secret, time.Now()) // SHA-1, 6, 30с

	req, _ := http.NewRequest("POST", service+"/tokens",
		strings.NewReader(`{"sub":"svc-a","aud":["svc-b"]}`))
	req.Header.Set("X-TOTP-Code", code)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "example.com"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
