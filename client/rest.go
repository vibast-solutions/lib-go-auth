package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type RESTClient struct {
	baseURL    string
	httpClient *http.Client
}

type RESTClientOption func(*RESTClient)

func WithHTTPClient(client *http.Client) RESTClientOption {
	return func(c *RESTClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func NewRESTClient(baseURL string, opts ...RESTClientOption) (*RESTClient, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New("baseURL is required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, err
	}

	client := &RESTClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

type APIError struct {
	StatusCode int
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", http.StatusText(e.StatusCode), e.Message)
	}
	return fmt.Sprintf("%s: %s", http.StatusText(e.StatusCode), e.Body)
}

func (c *RESTClient) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	return doPost[RegisterResponse](ctx, c, "/auth/register", req, "")
}

func (c *RESTClient) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	return doPost[LoginResponse](ctx, c, "/auth/login", req, "")
}

func (c *RESTClient) Logout(ctx context.Context, req LogoutRequest) (LogoutResponse, error) {
	payload := struct {
		RefreshToken string `json:"refresh_token"`
	}{
		RefreshToken: req.RefreshToken,
	}
	return doPost[LogoutResponse](ctx, c, "/auth/logout", payload, req.AccessToken)
}

func (c *RESTClient) ChangePassword(ctx context.Context, req ChangePasswordRequest) (ChangePasswordResponse, error) {
	payload := struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}
	return doPost[ChangePasswordResponse](ctx, c, "/auth/change-password", payload, req.AccessToken)
}

func (c *RESTClient) ConfirmAccount(ctx context.Context, req ConfirmAccountRequest) (ConfirmAccountResponse, error) {
	return doPost[ConfirmAccountResponse](ctx, c, "/auth/confirm-account", req, "")
}

func (c *RESTClient) RequestPasswordReset(ctx context.Context, req RequestPasswordResetRequest) (RequestPasswordResetResponse, error) {
	return doPost[RequestPasswordResetResponse](ctx, c, "/auth/request-password-reset", req, "")
}

func (c *RESTClient) ResetPassword(ctx context.Context, req ResetPasswordRequest) (ResetPasswordResponse, error) {
	return doPost[ResetPasswordResponse](ctx, c, "/auth/reset-password", req, "")
}

func (c *RESTClient) RefreshToken(ctx context.Context, req RefreshTokenRequest) (RefreshTokenResponse, error) {
	return doPost[RefreshTokenResponse](ctx, c, "/auth/refresh-token", req, "")
}

func (c *RESTClient) GenerateConfirmToken(ctx context.Context, req GenerateConfirmTokenRequest) (GenerateConfirmTokenResponse, error) {
	return doPost[GenerateConfirmTokenResponse](ctx, c, "/auth/generate-confirm-token", req, "")
}

func (c *RESTClient) ValidateToken(ctx context.Context, req ValidateTokenRequest) (ValidateTokenResponse, error) {
	return doPost[ValidateTokenResponse](ctx, c, "/auth/validate-token", req, "")
}

func doPost[T any](ctx context.Context, c *RESTClient, path string, payload any, accessToken string) (T, error) {
	var zero T

	data, err := json.Marshal(payload)
	if err != nil {
		return zero, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	body, err := readAll(resp)
	if err != nil {
		return zero, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		var parsed struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &parsed) == nil {
			if parsed.Error != "" {
				apiErr.Message = parsed.Error
			} else if parsed.Message != "" {
				apiErr.Message = parsed.Message
			}
		}
		return zero, apiErr
	}

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, err
	}
	return out, nil
}

const maxResponseSize = 1 << 20 // 1MB

func readAll(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}
