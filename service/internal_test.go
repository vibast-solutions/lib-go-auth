package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/vibast-solutions/lib-go-auth/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type stubInternalClient struct {
	resp client.InternalAccessResponse
	err  error
}

func (s *stubInternalClient) ValidateInternalAccess(context.Context, client.InternalAccessRequest) (client.InternalAccessResponse, error) {
	return s.resp, s.err
}

func TestValidateInternalAPIKey_Missing(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{})

	_, err := svc.ValidateInternalAPIKey(context.Background(), "")
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("expected ErrMissingAPIKey, got %v", err)
	}
}

func TestValidateInternalAPIKey_Unauthorized(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		err: &client.APIError{StatusCode: http.StatusUnauthorized},
	})

	_, err := svc.ValidateInternalAPIKey(context.Background(), "key")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestValidateInternalAPIKey_NotFoundHTTP(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		err: &client.APIError{StatusCode: http.StatusNotFound},
	})

	_, err := svc.ValidateInternalAPIKey(context.Background(), "key")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestValidateInternalAPIKey_UnauthenticatedGRPC(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		err: status.Error(codes.Unauthenticated, "invalid"),
	})

	_, err := svc.ValidateInternalAPIKey(context.Background(), "key")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestValidateInternalAPIKey_NotFoundGRPC(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		err: status.Error(codes.NotFound, "not found"),
	})

	_, err := svc.ValidateInternalAPIKey(context.Background(), "key")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestAuthenticateInternal_Success(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"auth", "notifications"},
		},
	})

	serviceName, allowed, err := svc.AuthenticateInternal(context.Background(), "key")
	if err != nil {
		t.Fatalf("authenticate internal failed: %v", err)
	}
	if serviceName != "profile-service" {
		t.Fatalf("expected service name profile-service, got %q", serviceName)
	}
	if len(allowed) != 2 {
		t.Fatalf("expected allowed access entries, got %#v", allowed)
	}
}

func TestAuthorizeInternal_Denied(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"auth"},
		},
	})

	_, err := svc.AuthorizeInternal(context.Background(), "key", "notifications")
	if !errors.Is(err, ErrInternalAPIDenied) {
		t.Fatalf("expected ErrInternalAPIDenied, got %v", err)
	}
}

func TestAuthorizeInternal_Success(t *testing.T) {
	svc := NewInternalAuthService(&stubInternalClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"auth", "notifications"},
		},
	})

	resp, err := svc.AuthorizeInternal(context.Background(), "key", "notifications")
	if err != nil {
		t.Fatalf("authorize internal failed: %v", err)
	}
	if resp.ServiceName != "profile-service" {
		t.Fatalf("expected profile-service, got %q", resp.ServiceName)
	}
}
