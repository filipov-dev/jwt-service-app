// Package main — клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
//
// Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
// токена и массовый отзыв токенов субъекта.
//
// Зависимости: go get github.com/pquerna/otp
//
// Окружение:
//   - AUTH_TOTP_SECRET — общий TOTP-секрет в base32 (обязательно);
//   - JWT_SERVICE_URL — базовый URL сервиса, по умолчанию http://localhost:8080.
//
// Код считается заново перед каждым запросом: при включённой на сервере защите от
// переигрывания (AUTH_TOTP_REPLAY_PROTECTION) повторное предъявление того же кода
// вернёт 401, хотя сам код ещё не истёк.
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

// issuerHost — значение claim iss. Должно совпадать при выпуске и проверке.
const issuerHost = "example.com"

// TokenResponse — ответ на выпуск токена или обмен refresh-токена.
type TokenResponse struct {
	// Token — подписанный JWT в формате header.payload.signature.
	Token string `json:"token"`
	// RefreshToken присутствует, только если запрашивался.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// RevokeGroupResponse — ответ на массовый отзыв токенов субъекта.
type RevokeGroupResponse struct {
	// Revoked — сколько активных токенов отозвано; истёкшие не считаются.
	Revoked int `json:"revoked"`
}

// Client — клиент сервиса выдачи токенов.
type Client struct {
	// BaseURL — базовый URL сервиса.
	BaseURL string
	// Secret — общий TOTP-секрет в base32.
	Secret string
	// HTTP — используемый HTTP-клиент.
	HTTP *http.Client
}

// NewClient собирает клиент из переменных окружения.
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

// totpCode вычисляет TOTP-код на текущий момент.
//
// Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
func (c *Client) totpCode() (string, error) {
	return totp.GenerateCode(c.Secret, time.Now())
}

// do выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
//
// body может быть nil для запросов без тела (отзыв).
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

	// Код считается здесь, а не переиспользуется: один код — один запрос.
	code, err := c.totpCode()
	if err != nil {
		return nil, err
	}

	request.Header.Set("X-TOTP-Code", code)
	request.Header.Set("Content-Type", "application/json")
	request.Host = issuerHost

	return c.HTTP.Do(request)
}

// IssueToken выпускает access-токен (POST /tokens).
//
// sub — субъект (claim sub), aud — список получателей (claim aud, не пустой),
// withRefresh — запросить вместе с токеном refresh для продления сессии,
// claims — произвольные claims (роли, scope, tenant), которые попадут в payload
// рядом с зарегистрированными; nil, если они не нужны.
//
// Служебные имена (iss, sub, aud, exp, iat, nbf, jti) переопределять нельзя —
// сервис ответит 422. Число ключей и объём ограничены на сервере.
//
// Возвращает ошибку при 401 (неверный код), 422 (некорректные параметры или
// запрещённый claim) и 500 (недоступны JWKS или Redis).
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
		return nil, fmt.Errorf("выпуск не удался: %s", response.Status)
	}

	var issued TokenResponse
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		return nil, err
	}
	return &issued, nil
}

// RefreshTokens обменивает refresh-токен на новую пару (POST /tokens/refresh).
//
// Старый токен после обмена недействителен: сохраните новый и выбросьте
// предыдущий.
//
// ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
// предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
// выданные по ним access-токены. Надёжнее выпустить пару заново.
func (c *Client) RefreshTokens(refreshToken string) (*TokenResponse, error) {
	payload := map[string]string{"refresh_token": refreshToken}

	response, err := c.do(http.MethodPost, "/tokens/refresh", payload)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("обмен не удался: %s", response.Status)
	}

	var refreshed TokenResponse
	if err := json.NewDecoder(response.Body).Decode(&refreshed); err != nil {
		return nil, err
	}
	return &refreshed, nil
}

// RevokeToken отзывает один токен по его jti (DELETE /tokens/{jti}).
//
// Идемпотентно: отзыв несуществующего jti — тоже успех. Ошибка означает, что
// хранилище недоступно и отзыв НЕ выполнен, — попытку следует повторить.
func (c *Client) RevokeToken(jti string) error {
	response, err := c.do(http.MethodDelete, "/tokens/"+jti, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("отзыв не удался: %s", response.Status)
	}
	return nil
}

// RevokeSubject отзывает все активные токены субъекта.
//
// Ручка DELETE /subjects/{sub}/tokens. Нужна при компрометации: гасить токены по
// одному нельзя, их jti вызывающему неизвестны. Возвращает число отозванных
// токенов; уже истёкшие не считаются.
func (c *Client) RevokeSubject(sub string) (int, error) {
	response, err := c.do(http.MethodDelete, "/subjects/"+sub+"/tokens", nil)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("массовый отзыв не удался: %s", response.Status)
	}

	var revoked RevokeGroupResponse
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		return 0, err
	}
	return revoked.Revoked, nil
}

// main демонстрирует полный жизненный цикл токена.
func main() {
	client := NewClient()

	issued, err := client.IssueToken("svc-a", []string{"svc-b"}, true,
		map[string]any{"role": "admin"})
	if err != nil {
		panic(err)
	}
	fmt.Println("выпущен:", issued.Token[:32], "...")

	refreshed, err := client.RefreshTokens(issued.RefreshToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("обновлён:", refreshed.Token[:32], "...")

	count, err := client.RevokeSubject("svc-a")
	if err != nil {
		panic(err)
	}
	fmt.Println("отозвано токенов:", count)
}
