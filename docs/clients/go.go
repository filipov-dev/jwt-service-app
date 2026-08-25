// Package main is a jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//
// Install: go get github.com/pquerna/otp
// Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).
// See README.md for endpoints, error codes and client rules.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
)

// issuerHost is sent as the Host header and becomes the iss claim.
const issuerHost = "example.com"

// TokenResponse is the reply of an issue or refresh call.
type TokenResponse struct {
	// Token is a signed JWT: header.payload.signature.
	Token string `json:"token"`
	// RefreshToken is present only when it was requested.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// RevokeGroupResponse is the reply of a bulk revoke call.
type RevokeGroupResponse struct {
	// Revoked is the number of revoked tokens.
	Revoked int `json:"revoked"`
}

// Client is a client of the token service.
type Client struct {
	BaseURL string
	Secret  string
	HTTP    *http.Client
}

// NewClient builds a client from the environment.
func NewClient() *Client {
	service := os.Getenv("JWT_SERVICE_URL")
	if service == "" {
		service = "http://localhost:8080"
	}

	return &Client{
		BaseURL: service,
		Secret:  os.Getenv("AUTH_TOTP_SECRET"),
		HTTP:    &http.Client{Timeout: 5 * time.Second},
	}
}

// totpCode returns a fresh code: SHA-1, 6 digits, 30-second step.
func (c *Client) totpCode() (string, error) {
	return totp.GenerateCode(c.Secret, time.Now())
}

// do sends a level 3 request with a code computed right before the call.
// body may be nil for requests without one.
func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}

	code, err := c.totpCode()
	if err != nil {
		return nil, err
	}

	request.Header.Set("X-TOTP-Code", code)
	request.Header.Set("Content-Type", "application/json")
	request.Host = issuerHost

	return c.HTTP.Do(request)
}

// IssueToken calls POST /tokens. claims may be nil.
func (c *Client) IssueToken(
	sub string,
	aud []string,
	withRefresh bool,
	claims map[string]any,
) (*TokenResponse, error) {
	payload := map[string]any{"sub": sub, "aud": aud, "refresh": withRefresh}
	if len(claims) > 0 {
		payload["claims"] = claims
	}

	response, err := c.do(http.MethodPost, "/tokens", payload)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issue failed: %s", response.Status)
	}

	var issued TokenResponse
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		return nil, err
	}
	return &issued, nil
}

// RefreshTokens calls POST /tokens/refresh and returns a new pair.
// The old refresh token is dead once the call succeeds.
func (c *Client) RefreshTokens(refreshToken string) (*TokenResponse, error) {
	payload := map[string]string{"refresh_token": refreshToken}

	response, err := c.do(http.MethodPost, "/tokens/refresh", payload)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed: %s", response.Status)
	}

	var refreshed TokenResponse
	if err := json.NewDecoder(response.Body).Decode(&refreshed); err != nil {
		return nil, err
	}
	return &refreshed, nil
}

// RevokeToken calls DELETE /tokens/{jti}. Idempotent.
func (c *Client) RevokeToken(jti string) error {
	response, err := c.do(http.MethodDelete, "/tokens/"+jti, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoke failed: %s", response.Status)
	}
	return nil
}

// RevokeSubject calls DELETE /subjects/{sub}/tokens and returns how many
// tokens were revoked.
func (c *Client) RevokeSubject(sub string) (int, error) {
	response, err := c.do(http.MethodDelete, "/subjects/"+sub+"/tokens", nil)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bulk revoke failed: %s", response.Status)
	}

	var revoked RevokeGroupResponse
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		return 0, err
	}
	return revoked.Revoked, nil
}

// main runs issue -> refresh -> revoke.
func main() {
	client := NewClient()

	issued, err := client.IssueToken("svc-a", []string{"svc-b"}, true,
		map[string]any{"role": "admin"})
	if err != nil {
		panic(err)
	}
	fmt.Println("issued:", issued.Token[:32], "...")

	refreshed, err := client.RefreshTokens(issued.RefreshToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("refreshed:", refreshed.Token[:32], "...")

	count, err := client.RevokeSubject("svc-a")
	if err != nil {
		panic(err)
	}
	fmt.Println("revoked:", count)
}
