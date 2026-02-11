package client

import (
	"context"

	authpb "github.com/vibast-solutions/ms-go-auth/app/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type GRPCClient struct {
	client    authpb.AuthServiceClient
	conn      *grpc.ClientConn
	apiKey    string
	apiKeyErr error
}

func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient {
	client := &GRPCClient{
		client: authpb.NewAuthServiceClient(conn),
		conn:   conn,
	}

	apiKey, err := requiredAPIKeyFromEnv()
	if err != nil {
		client.apiKeyErr = err
		return client
	}
	client.apiKey = apiKey

	return client
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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return RegisterResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return LoginResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return LogoutResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return ChangePasswordResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return ConfirmAccountResponse{}, err
	}

	resp, err := c.client.ConfirmAccount(ctx, &authpb.ConfirmAccountRequest{
		Token: req.Token,
	})
	if err != nil {
		return ConfirmAccountResponse{}, err
	}
	return ConfirmAccountResponse{Message: resp.Message}, nil
}

func (c *GRPCClient) RequestPasswordReset(ctx context.Context, req RequestPasswordResetRequest) (RequestPasswordResetResponse, error) {
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return RequestPasswordResetResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return ResetPasswordResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return RefreshTokenResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return GenerateConfirmTokenResponse{}, err
	}

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
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return ValidateTokenResponse{}, err
	}

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

func (c *GRPCClient) ValidateInternalAccess(ctx context.Context, req InternalAccessRequest) (InternalAccessResponse, error) {
	ctx, err := c.withAPIKey(ctx)
	if err != nil {
		return InternalAccessResponse{}, err
	}

	resp, err := c.client.ValidateInternalAccess(ctx, &authpb.ValidateInternalAccessRequest{
		ApiKey: req.APIKey,
	})
	if err != nil {
		return InternalAccessResponse{}, err
	}
	return InternalAccessResponse{
		ServiceName:   resp.ServiceName,
		AllowedAccess: resp.AllowedAccess,
	}, nil
}

func (c *GRPCClient) withAPIKey(ctx context.Context) (context.Context, error) {
	if c.apiKeyErr != nil {
		return nil, c.apiKeyErr
	}

	return metadata.AppendToOutgoingContext(ctx, "x-api-key", c.apiKey), nil
}
