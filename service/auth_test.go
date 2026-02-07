package service

import (
	"context"
	"errors"
	"testing"

	"github.com/vibast-solutions/lib-go-auth/client"
)

type stubClient struct {
	validateResp client.ValidateTokenResponse
	validateErr  error
}

func (s *stubClient) Register(context.Context, client.RegisterRequest) (client.RegisterResponse, error) {
	return client.RegisterResponse{}, nil
}
func (s *stubClient) Login(context.Context, client.LoginRequest) (client.LoginResponse, error) {
	return client.LoginResponse{}, nil
}
func (s *stubClient) Logout(context.Context, client.LogoutRequest) (client.LogoutResponse, error) {
	return client.LogoutResponse{}, nil
}
func (s *stubClient) ChangePassword(context.Context, client.ChangePasswordRequest) (client.ChangePasswordResponse, error) {
	return client.ChangePasswordResponse{}, nil
}
func (s *stubClient) ConfirmAccount(context.Context, client.ConfirmAccountRequest) (client.ConfirmAccountResponse, error) {
	return client.ConfirmAccountResponse{}, nil
}
func (s *stubClient) RequestPasswordReset(context.Context, client.RequestPasswordResetRequest) (client.RequestPasswordResetResponse, error) {
	return client.RequestPasswordResetResponse{}, nil
}
func (s *stubClient) ResetPassword(context.Context, client.ResetPasswordRequest) (client.ResetPasswordResponse, error) {
	return client.ResetPasswordResponse{}, nil
}
func (s *stubClient) RefreshToken(context.Context, client.RefreshTokenRequest) (client.RefreshTokenResponse, error) {
	return client.RefreshTokenResponse{}, nil
}
func (s *stubClient) GenerateConfirmToken(context.Context, client.GenerateConfirmTokenRequest) (client.GenerateConfirmTokenResponse, error) {
	return client.GenerateConfirmTokenResponse{}, nil
}
func (s *stubClient) ValidateToken(context.Context, client.ValidateTokenRequest) (client.ValidateTokenResponse, error) {
	return s.validateResp, s.validateErr
}

func TestValidateAccessToken_Missing(t *testing.T) {
	svc := NewAuthService(&stubClient{})
	_, err := svc.ValidateAccessToken(context.Background(), "")
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("expected ErrMissingToken, got %v", err)
	}
}

func TestValidateAccessToken_Invalid(t *testing.T) {
	svc := NewAuthService(&stubClient{
		validateResp: client.ValidateTokenResponse{Valid: false},
	})
	_, err := svc.ValidateAccessToken(context.Background(), "token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestAuthenticate_Success(t *testing.T) {
	svc := NewAuthService(&stubClient{
		validateResp: client.ValidateTokenResponse{Valid: true, UserID: 1, Email: "user@example.com"},
	})
	userID, email, err := svc.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if userID != 1 || email != "user@example.com" {
		t.Fatalf("unexpected result: %d %s", userID, email)
	}
}

func TestValidateAccessToken_PropagatesClientError(t *testing.T) {
	backendErr := errors.New("backend error")
	svc := NewAuthService(&stubClient{
		validateErr: backendErr,
	})
	_, err := svc.ValidateAccessToken(context.Background(), "token")
	if err == nil || !errors.Is(err, backendErr) {
		t.Fatalf("expected backend error, got %v", err)
	}
}
