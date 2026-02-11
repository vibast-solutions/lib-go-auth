package client

import (
	"context"
	"net"
	"testing"

	authpb "github.com/vibast-solutions/ms-go-auth/app/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type testAuthServer struct {
	authpb.UnimplementedAuthServiceServer
	lastTokenDuration int64
	lastRegister      *authpb.RegisterRequest
	lastChange        *authpb.ChangePasswordRequest
	lastLogout        *authpb.LogoutRequest
	lastRefresh       *authpb.RefreshTokenRequest
	lastInternal      *authpb.ValidateInternalAccessRequest
	lastAPIKey        string
}

func (s *testAuthServer) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		values := md.Get("x-api-key")
		if len(values) > 0 {
			s.lastAPIKey = values[0]
		}
	}
	s.lastTokenDuration = req.TokenDuration
	return &authpb.LoginResponse{
		AccessToken:  "a",
		RefreshToken: "b",
		ExpiresIn:    10,
	}, nil
}

func (s *testAuthServer) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	s.lastRegister = req
	return &authpb.RegisterResponse{
		UserId: 1,
		Email:  req.Email,
	}, nil
}

func (s *testAuthServer) ChangePassword(ctx context.Context, req *authpb.ChangePasswordRequest) (*authpb.ChangePasswordResponse, error) {
	s.lastChange = req
	return &authpb.ChangePasswordResponse{Message: "ok"}, nil
}

func (s *testAuthServer) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	s.lastLogout = req
	return &authpb.LogoutResponse{Message: "ok"}, nil
}

func (s *testAuthServer) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest) (*authpb.RefreshTokenResponse, error) {
	s.lastRefresh = req
	return &authpb.RefreshTokenResponse{AccessToken: "a", RefreshToken: "b", ExpiresIn: 10}, nil
}

func (s *testAuthServer) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	return &authpb.ValidateTokenResponse{
		Valid:  true,
		UserId: 1,
		Email:  "user@example.com",
	}, nil
}

func (s *testAuthServer) ValidateInternalAccess(ctx context.Context, req *authpb.ValidateInternalAccessRequest) (*authpb.ValidateInternalAccessResponse, error) {
	s.lastInternal = req
	return &authpb.ValidateInternalAccessResponse{
		ServiceName:   "profile-service",
		AllowedAccess: []string{"auth", "notifications"},
	}, nil
}

func newTestGRPCServer(t *testing.T) (*grpc.Server, *grpc.ClientConn, *testAuthServer, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	srv := grpc.NewServer()
	handler := &testAuthServer{}
	authpb.RegisterAuthServiceServer(srv, handler)

	go func() {
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc new client failed: %v", err)
	}

	cleanup := func() {
		conn.Close()
		srv.Stop()
		lis.Close()
	}

	return srv, conn, handler, cleanup
}

func TestGRPCClient_Login_TokenDurationMapping(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	duration := int64(42)
	_, err := client.Login(context.Background(), LoginRequest{
		Email:         "user@example.com",
		Password:      "pass",
		TokenDuration: &duration,
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if handler.lastTokenDuration != 42 {
		t.Fatalf("expected token_duration 42, got %d", handler.lastTokenDuration)
	}
}

func TestGRPCClient_ValidateToken(t *testing.T) {
	_, conn, _, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	resp, err := client.ValidateToken(context.Background(), ValidateTokenRequest{AccessToken: "token"})
	if err != nil {
		t.Fatalf("validate token failed: %v", err)
	}
	if !resp.Valid || resp.UserID != 1 || resp.Email != "user@example.com" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGRPCClient_ValidateInternalAccess(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	resp, err := client.ValidateInternalAccess(context.Background(), InternalAccessRequest{APIKey: "key"})
	if err != nil {
		t.Fatalf("validate internal access failed: %v", err)
	}
	if resp.ServiceName != "profile-service" || len(resp.AllowedAccess) != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if handler.lastInternal == nil || handler.lastInternal.ApiKey != "key" {
		t.Fatalf("expected ValidateInternalAccess to be called with api key")
	}
}

func TestGRPCClient_AttachesEnvAPIKeyMetadata(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	_, err := client.Login(context.Background(), LoginRequest{Email: "user@example.com", Password: "pass"})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if handler.lastAPIKey != "service-key" {
		t.Fatalf("expected x-api-key metadata from env, got %q", handler.lastAPIKey)
	}
}

func TestGRPCClient_RequiresAPPAPIKey(t *testing.T) {
	t.Setenv(appAPIKeyEnvVar, "")

	_, conn, _, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	_, err := client.Login(context.Background(), LoginRequest{Email: "user@example.com", Password: "pass"})
	if err == nil {
		t.Fatalf("expected error when %s is missing", appAPIKeyEnvVar)
	}
}

func TestGRPCClient_Register(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	res, err := client.Register(context.Background(), RegisterRequest{Email: "user@example.com", Password: "pass"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if res.UserID != 1 || res.Email != "user@example.com" {
		t.Fatalf("unexpected response: %+v", res)
	}
	if handler.lastRegister == nil || handler.lastRegister.Email != "user@example.com" {
		t.Fatalf("expected register to be called")
	}
}

func TestGRPCClient_ChangePassword(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	_, err := client.ChangePassword(context.Background(), ChangePasswordRequest{
		AccessToken: "token",
		OldPassword: "old",
		NewPassword: "new",
	})
	if err != nil {
		t.Fatalf("change password failed: %v", err)
	}
	if handler.lastChange == nil || handler.lastChange.AccessToken != "token" {
		t.Fatalf("expected change password to be called")
	}
}

func TestGRPCClient_Logout(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	_, err := client.Logout(context.Background(), LogoutRequest{AccessToken: "a", RefreshToken: "r"})
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if handler.lastLogout == nil || handler.lastLogout.RefreshToken != "r" || handler.lastLogout.AccessToken != "a" {
		t.Fatalf("expected logout to be called")
	}
}

func TestGRPCClient_RefreshToken(t *testing.T) {
	_, conn, handler, cleanup := newTestGRPCServer(t)
	defer cleanup()

	client := NewGRPCClient(conn)
	res, err := client.RefreshToken(context.Background(), RefreshTokenRequest{RefreshToken: "r"})
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if res.RefreshToken != "b" || res.AccessToken != "a" {
		t.Fatalf("unexpected response: %+v", res)
	}
	if handler.lastRefresh == nil || handler.lastRefresh.RefreshToken != "r" {
		t.Fatalf("expected refresh token to be called")
	}
}
