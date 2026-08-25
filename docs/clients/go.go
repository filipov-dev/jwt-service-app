// Package main is a jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//
// Install: go get github.com/pquerna/otp
//
// Env:
//   - AUTH_TOTP_SECRET — shared TOTP secret, base32 (required);
//   - JWT_SERVICE_URL — service base URL, default http://localhost:8080.
//
// The code is recomputed before every request: with replay protection on
// (AUTH_TOTP_REPLAY_PROTECTION) the server rejects a code it has already seen
// with 401, even while that code is still inside its time window.
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

// issuerHost is sent as the Host header and becomes the iss claim. It must be
// the same on issue and on verify, or the token will not verify.
const issuerHost = "example.com"

// TokenResponse is the reply of an issue or a refresh call.
type TokenResponse struct {
	// Token is a signed JWT: header.payload.signature.
	Token string `json:"token"`
	// RefreshToken is present only if it was requested.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// RevokeGroupResponse is the reply of a bulk revoke call.
type RevokeGroupResponse struct {
	// Revoked is how many active tokens were killed; expired ones do not count.
	Revoked int `json:"revoked"`
}

// Client is a client of the token service, covering all four level 3 endpoints.
type Client struct {
	// BaseURL is the service base URL.
	BaseURL string
	// Secret is the shared TOTP secret, base32.
	Secret string
	// HTTP is the underlying HTTP client.
	HTTP *http.Client
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

// totpCode returns a fresh code for right now: SHA-1, 6 digits, 30-second step.
func (c *Client) totpCode() (string, error) {
	return totp.GenerateCode(c.Secret, time.Now())
}

// do sends a level 3 request.
//
// body may be nil for requests without one (revocation).
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

	// Computed here rather than reused: one code, one request.
	code, err := c.totpCode()
	if err != nil {
		return nil, err
	}

	request.Header.Set("X-TOTP-Code", code)
	request.Header.Set("Content-Type", "application/json")
	request.Host = issuerHost

	return c.HTTP.Do(request)
}

// IssueToken issues an access token (POST /tokens).
//
// sub is the subject (sub claim), aud the audience (aud claim, must not be
// empty), withRefresh also returns a refresh token for extending the session,
// and claims are custom values (role, scope, tenant) placed next to the
// registered ones, so the consumer reads role, not extra.role; pass nil when
// they are not needed.
//
// Reserved names (iss, sub, aud, exp, iat, nbf, jti) are rejected with 422 —
// change lifetime through ttl, not exp. Count and size are capped server-side.
//
// Returns an error on 401 (bad code), 422 (bad parameters or forbidden claim)
// and 500 (JWKS or Redis unavailable).
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

// RefreshTokens exchanges a refresh token for a new pair (POST /tokens/refresh).
//
// The old token dies on exchange: store the new one and drop the previous.
//
// Never retry an exchange with the old token when the reply is lost. A second
// presentation reads as theft, and the server revokes the whole family —
// refresh tokens and the access tokens issued from them. Issue a new pair
// instead. 401 means the token is unknown, expired or already used.
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

// RevokeToken revokes one token by its jti (DELETE /tokens/{jti}).
//
// Idempotent: revoking an unknown jti is success too. An error means the store
// is unreachable and the token is NOT revoked — retry.
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

// RevokeSubject revokes every active token of a subject.
//
// Endpoint DELETE /subjects/{sub}/tokens. The compromise path: tokens cannot be
// killed one by one because the caller does not know their jti. Returns the
// number of revoked tokens; expired ones do not count.
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

// main runs the full token lifecycle: issue, refresh, bulk revoke.
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
