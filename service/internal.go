package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/vibast-solutions/lib-go-auth/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrMissingAPIKey      = errors.New("missing api key")
	ErrInvalidAPIKey      = errors.New("invalid or expired api key")
	ErrInternalAPIDenied  = errors.New("api key does not have required access")
	ErrMissingTargetScope = errors.New("missing target service")
)

type InternalAuthService struct {
	client client.InternalAuthClient
}

func NewInternalAuthService(client client.InternalAuthClient) *InternalAuthService {
	return &InternalAuthService{client: client}
}

func (s *InternalAuthService) ValidateInternalAPIKey(ctx context.Context, apiKey string) (*client.InternalAccessResponse, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, ErrMissingAPIKey
	}

	resp, err := s.client.ValidateInternalAccess(ctx, client.InternalAccessRequest{APIKey: apiKey})
	if err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusNotFound {
				return nil, ErrInvalidAPIKey
			}
		}
		if st, ok := status.FromError(err); ok {
			if st.Code() == codes.Unauthenticated || st.Code() == codes.NotFound {
				return nil, ErrInvalidAPIKey
			}
		}
		return nil, fmt.Errorf("validating internal api key: %w", err)
	}

	return &resp, nil
}

func (s *InternalAuthService) AuthenticateInternal(ctx context.Context, apiKey string) (string, []string, error) {
	resp, err := s.ValidateInternalAPIKey(ctx, apiKey)
	if err != nil {
		return "", nil, err
	}

	return resp.ServiceName, resp.AllowedAccess, nil
}

func (s *InternalAuthService) AuthorizeInternal(ctx context.Context, apiKey, targetService string) (*client.InternalAccessResponse, error) {
	targetService = strings.TrimSpace(targetService)
	if targetService == "" {
		return nil, ErrMissingTargetScope
	}

	resp, err := s.ValidateInternalAPIKey(ctx, apiKey)
	if err != nil {
		return nil, err
	}

	for _, allowed := range resp.AllowedAccess {
		if allowed == targetService {
			return resp, nil
		}
	}

	return nil, ErrInternalAPIDenied
}
