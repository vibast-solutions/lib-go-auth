package client

import "context"

var (
	_ AuthClient = (*RESTClient)(nil)
	_ AuthClient = (*GRPCClient)(nil)
)

type AuthClient interface {
	Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error)
	Login(ctx context.Context, req LoginRequest) (LoginResponse, error)
	Logout(ctx context.Context, req LogoutRequest) (LogoutResponse, error)
	ChangePassword(ctx context.Context, req ChangePasswordRequest) (ChangePasswordResponse, error)
	ConfirmAccount(ctx context.Context, req ConfirmAccountRequest) (ConfirmAccountResponse, error)
	RequestPasswordReset(ctx context.Context, req RequestPasswordResetRequest) (RequestPasswordResetResponse, error)
	ResetPassword(ctx context.Context, req ResetPasswordRequest) (ResetPasswordResponse, error)
	RefreshToken(ctx context.Context, req RefreshTokenRequest) (RefreshTokenResponse, error)
	GenerateConfirmToken(ctx context.Context, req GenerateConfirmTokenRequest) (GenerateConfirmTokenResponse, error)
	ValidateToken(ctx context.Context, req ValidateTokenRequest) (ValidateTokenResponse, error)
}
