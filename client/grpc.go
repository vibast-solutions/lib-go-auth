package client

import (
	"context"

	authpb "github.com/vibast-solutions/ms-go-auth/app/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCClient struct {
	client authpb.AuthServiceClient
	conn   *grpc.ClientConn
}

func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient {
	return &GRPCClient{
		client: authpb.NewAuthServiceClient(conn),
		conn:   conn,
	}
}

func NewGRPCClientFromAddr(ctx context.Context, addr string, opts ...grpc.DialOption) (*GRPCClient, error) {
	if len(opts) == 0 {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return NewGRPCClient(conn), nil
}

func (c *GRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *GRPCClient) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	resp, err := c.client.Register(ctx, &authpb.RegisterRequest{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return RegisterResponse{}, err
	}
	return RegisterResponse{
		UserID:       resp.UserId,
		Email:        resp.Email,
		ConfirmToken: resp.ConfirmToken,
		Message:      resp.Message,
	}, nil
}

func (c *GRPCClient) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	var duration int64
	if req.TokenDuration != nil {
		duration = *req.TokenDuration
	}
	resp, err := c.client.Login(ctx, &authpb.LoginRequest{
		Email:         req.Email,
		Password:      req.Password,
		TokenDuration: duration,
	})
	if err != nil {
		return LoginResponse{}, err
	}
	return LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
	}, nil
}

func (c *GRPCClient) Logout(ctx context.Context, req LogoutRequest) (LogoutResponse, error) {
	resp, err := c.client.Logout(ctx, &authpb.LogoutRequest{
		RefreshToken: req.RefreshToken,
		AccessToken:  req.AccessToken,
	})
	if err != nil {
		return LogoutResponse{}, err
	}
	return LogoutResponse{Message: resp.Message}, nil
}

func (c *GRPCClient) ChangePassword(ctx context.Context, req ChangePasswordRequest) (ChangePasswordResponse, error) {
	resp, err := c.client.ChangePassword(ctx, &authpb.ChangePasswordRequest{
		AccessToken: req.AccessToken,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		return ChangePasswordResponse{}, err
	}
	return ChangePasswordResponse{Message: resp.Message}, nil
}

func (c *GRPCClient) ConfirmAccount(ctx context.Context, req ConfirmAccountRequest) (ConfirmAccountResponse, error) {
	resp, err := c.client.ConfirmAccount(ctx, &authpb.ConfirmAccountRequest{
		Token: req.Token,
	})
	if err != nil {
		return ConfirmAccountResponse{}, err
	}
	return ConfirmAccountResponse{Message: resp.Message}, nil
}

func (c *GRPCClient) RequestPasswordReset(ctx context.Context, req RequestPasswordResetRequest) (RequestPasswordResetResponse, error) {
	resp, err := c.client.RequestPasswordReset(ctx, &authpb.RequestPasswordResetRequest{
		Email: req.Email,
	})
	if err != nil {
		return RequestPasswordResetResponse{}, err
	}
	return RequestPasswordResetResponse{
		ResetToken: resp.ResetToken,
		Message:    resp.Message,
	}, nil
}

func (c *GRPCClient) ResetPassword(ctx context.Context, req ResetPasswordRequest) (ResetPasswordResponse, error) {
	resp, err := c.client.ResetPassword(ctx, &authpb.ResetPasswordRequest{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		return ResetPasswordResponse{}, err
	}
	return ResetPasswordResponse{Message: resp.Message}, nil
}

func (c *GRPCClient) RefreshToken(ctx context.Context, req RefreshTokenRequest) (RefreshTokenResponse, error) {
	resp, err := c.client.RefreshToken(ctx, &authpb.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		return RefreshTokenResponse{}, err
	}
	return RefreshTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
	}, nil
}

func (c *GRPCClient) GenerateConfirmToken(ctx context.Context, req GenerateConfirmTokenRequest) (GenerateConfirmTokenResponse, error) {
	resp, err := c.client.GenerateConfirmToken(ctx, &authpb.GenerateConfirmTokenRequest{
		Email: req.Email,
	})
	if err != nil {
		return GenerateConfirmTokenResponse{}, err
	}
	return GenerateConfirmTokenResponse{
		ConfirmToken: resp.ConfirmToken,
		Message:      resp.Message,
	}, nil
}

func (c *GRPCClient) ValidateToken(ctx context.Context, req ValidateTokenRequest) (ValidateTokenResponse, error) {
	resp, err := c.client.ValidateToken(ctx, &authpb.ValidateTokenRequest{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		return ValidateTokenResponse{}, err
	}
	return ValidateTokenResponse{
		Valid:  resp.Valid,
		UserID: resp.UserId,
		Email:  resp.Email,
	}, nil
}
