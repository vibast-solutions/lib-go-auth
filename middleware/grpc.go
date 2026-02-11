package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vibast-solutions/lib-go-auth/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type grpcCallerServiceKey struct{}
type grpcCallerAllowedAccessKey struct{}

func CallerServiceFromGRPCContext(ctx context.Context) (string, error) {
	v := ctx.Value(grpcCallerServiceKey{})
	if v == nil {
		return "", fmt.Errorf("caller_service not found in grpc context")
	}
	serviceName, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("caller_service has unexpected type %T", v)
	}
	return serviceName, nil
}

func CallerAllowedAccessFromGRPCContext(ctx context.Context) ([]string, error) {
	v := ctx.Value(grpcCallerAllowedAccessKey{})
	if v == nil {
		return nil, fmt.Errorf("caller_allowed_access not found in grpc context")
	}
	allowed, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("caller_allowed_access has unexpected type %T", v)
	}
	return allowed, nil
}

type GRPCInternalAuthMiddleware struct {
	authService *service.InternalAuthService
}

func NewGRPCInternalAuthMiddleware(authService *service.InternalAuthService) *GRPCInternalAuthMiddleware {
	return &GRPCInternalAuthMiddleware{authService: authService}
}

func (m *GRPCInternalAuthMiddleware) UnaryRequireInternalAuth() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return m.unaryWithMode(ctx, req, handler, "", false)
	}
}

func (m *GRPCInternalAuthMiddleware) UnaryRequireInternalAuthFor(methods ...string) grpc.UnaryServerInterceptor {
	protected := toMethodSet(methods)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !protected[info.FullMethod] {
			return handler(ctx, req)
		}
		return m.unaryWithMode(ctx, req, handler, "", false)
	}
}

func (m *GRPCInternalAuthMiddleware) UnaryRequireInternalAccess(targetService string) grpc.UnaryServerInterceptor {
	targetService = strings.TrimSpace(targetService)
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return m.unaryWithMode(ctx, req, handler, targetService, true)
	}
}

func (m *GRPCInternalAuthMiddleware) UnaryRequireInternalAccessFor(targetService string, methods ...string) grpc.UnaryServerInterceptor {
	targetService = strings.TrimSpace(targetService)
	protected := toMethodSet(methods)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !protected[info.FullMethod] {
			return handler(ctx, req)
		}
		return m.unaryWithMode(ctx, req, handler, targetService, true)
	}
}

func (m *GRPCInternalAuthMiddleware) StreamRequireInternalAuth() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return m.streamWithMode(srv, ss, handler, "", false)
	}
}

func (m *GRPCInternalAuthMiddleware) StreamRequireInternalAuthFor(methods ...string) grpc.StreamServerInterceptor {
	protected := toMethodSet(methods)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !protected[info.FullMethod] {
			return handler(srv, ss)
		}
		return m.streamWithMode(srv, ss, handler, "", false)
	}
}

func (m *GRPCInternalAuthMiddleware) StreamRequireInternalAccess(targetService string) grpc.StreamServerInterceptor {
	targetService = strings.TrimSpace(targetService)
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return m.streamWithMode(srv, ss, handler, targetService, true)
	}
}

func (m *GRPCInternalAuthMiddleware) StreamRequireInternalAccessFor(targetService string, methods ...string) grpc.StreamServerInterceptor {
	targetService = strings.TrimSpace(targetService)
	protected := toMethodSet(methods)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !protected[info.FullMethod] {
			return handler(srv, ss)
		}
		return m.streamWithMode(srv, ss, handler, targetService, true)
	}
}

func (m *GRPCInternalAuthMiddleware) unaryWithMode(ctx context.Context, req any, handler grpc.UnaryHandler, targetService string, withAccess bool) (any, error) {
	apiKey := incomingAPIKeyFromMetadata(ctx)
	if apiKey == "" {
		return nil, status.Error(codes.Unauthenticated, "missing x-api-key metadata")
	}

	serviceName, allowedAccess, err := m.authenticate(ctx, apiKey, targetService, withAccess)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, grpcCallerServiceKey{}, serviceName)
	ctx = context.WithValue(ctx, grpcCallerAllowedAccessKey{}, allowedAccess)
	return handler(ctx, req)
}

func (m *GRPCInternalAuthMiddleware) streamWithMode(srv any, ss grpc.ServerStream, handler grpc.StreamHandler, targetService string, withAccess bool) error {
	apiKey := incomingAPIKeyFromMetadata(ss.Context())
	if apiKey == "" {
		return status.Error(codes.Unauthenticated, "missing x-api-key metadata")
	}

	serviceName, allowedAccess, err := m.authenticate(ss.Context(), apiKey, targetService, withAccess)
	if err != nil {
		return err
	}

	ctx := context.WithValue(ss.Context(), grpcCallerServiceKey{}, serviceName)
	ctx = context.WithValue(ctx, grpcCallerAllowedAccessKey{}, allowedAccess)
	return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})
}

func (m *GRPCInternalAuthMiddleware) authenticate(ctx context.Context, apiKey, targetService string, withAccess bool) (string, []string, error) {
	if withAccess {
		resp, err := m.authService.AuthorizeInternal(ctx, apiKey, targetService)
		if err != nil {
			if errors.Is(err, service.ErrInternalAPIDenied) {
				return "", nil, status.Error(codes.PermissionDenied, "forbidden")
			}
			return "", nil, status.Error(codes.Unauthenticated, "invalid or expired api key")
		}
		return resp.ServiceName, resp.AllowedAccess, nil
	}

	serviceName, allowedAccess, err := m.authService.AuthenticateInternal(ctx, apiKey)
	if err != nil {
		return "", nil, status.Error(codes.Unauthenticated, "invalid or expired api key")
	}
	return serviceName, allowedAccess, nil
}

func incomingAPIKeyFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("x-api-key")
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func toMethodSet(methods []string) map[string]bool {
	set := make(map[string]bool, len(methods))
	for _, method := range methods {
		method = strings.TrimSpace(method)
		if method == "" {
			continue
		}
		set[method] = true
	}
	return set
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
