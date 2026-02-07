package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vibast-solutions/lib-go-auth/client"
)

var (
	ErrMissingToken = errors.New("missing access token")
	ErrInvalidToken = errors.New("invalid or expired token")
)

type AuthService struct {
	client client.AuthClient
}

func NewAuthService(client client.AuthClient) *AuthService {
	return &AuthService{client: client}
}

func (s *AuthService) ValidateAccessToken(ctx context.Context, accessToken string) (*client.ValidateTokenResponse, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, ErrMissingToken
	}

	resp, err := s.client.ValidateToken(ctx, client.ValidateTokenRequest{
		AccessToken: accessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("validating token: %w", err)
	}
	if !resp.Valid {
		return nil, ErrInvalidToken
	}
	return &resp, nil
}

func (s *AuthService) Authenticate(ctx context.Context, accessToken string) (uint64, string, error) {
	resp, err := s.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return 0, "", err
	}
	return resp.UserID, resp.Email, nil
}
