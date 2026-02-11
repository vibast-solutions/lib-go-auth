package middleware

import (
	"context"
	"net/http"
	"testing"

	"github.com/vibast-solutions/lib-go-auth/client"
	"github.com/vibast-solutions/lib-go-auth/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type stubInternalGRPCClient struct {
	resp client.InternalAccessResponse
	err  error
}

func (s *stubInternalGRPCClient) ValidateInternalAccess(context.Context, client.InternalAccessRequest) (client.InternalAccessResponse, error) {
	return s.resp, s.err
}

func TestUnaryRequireInternalAuth_MissingAPIKey(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalGRPCClient{})
	mw := NewGRPCInternalAuthMiddleware(internalSvc)

	interceptor := mw.UnaryRequireInternalAuth()
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}

func TestUnaryRequireInternalAuth_SetsContext(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalGRPCClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"notifications"},
		},
	})
	mw := NewGRPCInternalAuthMiddleware(internalSvc)

	interceptor := mw.UnaryRequireInternalAuth()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "key"))

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}, func(ctx context.Context, req any) (any, error) {
		serviceName, err := CallerServiceFromGRPCContext(ctx)
		if err != nil {
			t.Fatalf("expected caller service in grpc context: %v", err)
		}
		if serviceName != "profile-service" {
			t.Fatalf("unexpected service name %q", serviceName)
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestUnaryRequireInternalAccess_PermissionDenied(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalGRPCClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"auth"},
		},
	})
	mw := NewGRPCInternalAuthMiddleware(internalSvc)

	interceptor := mw.UnaryRequireInternalAccess("notifications")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "key"))

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestUnaryRequireInternalAccessFor_OnlySelectedMethodsProtected(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalGRPCClient{
		err: &client.APIError{StatusCode: http.StatusUnauthorized},
	})
	mw := NewGRPCInternalAuthMiddleware(internalSvc)
	interceptor := mw.UnaryRequireInternalAccessFor("notifications", "/pkg.Svc/Protected")

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Open"}, func(ctx context.Context, req any) (any, error) {
		return "open-ok", nil
	})
	if err != nil {
		t.Fatalf("expected open method to bypass auth, got %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "key"))
	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Protected"}, func(ctx context.Context, req any) (any, error) {
		return "protected-ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated for protected method, got %v", err)
	}
}
