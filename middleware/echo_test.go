package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/vibast-solutions/lib-go-auth/client"
	"github.com/vibast-solutions/lib-go-auth/service"
)

type stubAuthClient struct {
	resp client.ValidateTokenResponse
	err  error
}

func (s *stubAuthClient) Register(ctx context.Context, req client.RegisterRequest) (client.RegisterResponse, error) {
	return client.RegisterResponse{}, nil
}
func (s *stubAuthClient) Login(ctx context.Context, req client.LoginRequest) (client.LoginResponse, error) {
	return client.LoginResponse{}, nil
}
func (s *stubAuthClient) Logout(ctx context.Context, req client.LogoutRequest) (client.LogoutResponse, error) {
	return client.LogoutResponse{}, nil
}
func (s *stubAuthClient) ChangePassword(ctx context.Context, req client.ChangePasswordRequest) (client.ChangePasswordResponse, error) {
	return client.ChangePasswordResponse{}, nil
}
func (s *stubAuthClient) ConfirmAccount(ctx context.Context, req client.ConfirmAccountRequest) (client.ConfirmAccountResponse, error) {
	return client.ConfirmAccountResponse{}, nil
}
func (s *stubAuthClient) RequestPasswordReset(ctx context.Context, req client.RequestPasswordResetRequest) (client.RequestPasswordResetResponse, error) {
	return client.RequestPasswordResetResponse{}, nil
}
func (s *stubAuthClient) ResetPassword(ctx context.Context, req client.ResetPasswordRequest) (client.ResetPasswordResponse, error) {
	return client.ResetPasswordResponse{}, nil
}
func (s *stubAuthClient) RefreshToken(ctx context.Context, req client.RefreshTokenRequest) (client.RefreshTokenResponse, error) {
	return client.RefreshTokenResponse{}, nil
}
func (s *stubAuthClient) GenerateConfirmToken(ctx context.Context, req client.GenerateConfirmTokenRequest) (client.GenerateConfirmTokenResponse, error) {
	return client.GenerateConfirmTokenResponse{}, nil
}
func (s *stubAuthClient) ValidateToken(ctx context.Context, req client.ValidateTokenRequest) (client.ValidateTokenResponse, error) {
	return s.resp, s.err
}

func TestRequireAuth_MissingHeader(t *testing.T) {
	authSvc := service.NewAuthService(&stubAuthClient{})
	mw := NewEchoAuthMiddleware(authSvc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := mw.RequireAuth(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuth_SetsContext(t *testing.T) {
	authSvc := service.NewAuthService(&stubAuthClient{
		resp: client.ValidateTokenResponse{
			Valid:  true,
			UserID: 1,
			Email:  "user@example.com",
		},
	})
	mw := NewEchoAuthMiddleware(authSvc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := mw.RequireAuth(func(c echo.Context) error {
		if c.Get("user_id") != uint64(1) {
			t.Fatalf("expected user_id 1, got %v", c.Get("user_id"))
		}
		if c.Get("user_email") != "user@example.com" {
			t.Fatalf("expected user_email, got %v", c.Get("user_email"))
		}
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireAuth_InvalidHeader(t *testing.T) {
	authSvc := service.NewAuthService(&stubAuthClient{})
	mw := NewEchoAuthMiddleware(authSvc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := mw.RequireAuth(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
