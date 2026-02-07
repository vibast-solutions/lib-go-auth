package client

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	UserID       uint64 `json:"user_id"`
	Email        string `json:"email"`
	ConfirmToken string `json:"confirm_token"`
	Message      string `json:"message"`
}

type LoginRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	TokenDuration *int64 `json:"token_duration,omitempty"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type LogoutRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}

type ChangePasswordRequest struct {
	AccessToken string `json:"access_token"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ChangePasswordResponse struct {
	Message string `json:"message"`
}

type ConfirmAccountRequest struct {
	Token string `json:"token"`
}

type ConfirmAccountResponse struct {
	Message string `json:"message"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

type RequestPasswordResetResponse struct {
	ResetToken string `json:"reset_token"`
	Message    string `json:"message"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type GenerateConfirmTokenRequest struct {
	Email string `json:"email"`
}

type GenerateConfirmTokenResponse struct {
	ConfirmToken string `json:"confirm_token"`
	Message      string `json:"message"`
}

type ValidateTokenRequest struct {
	AccessToken string `json:"access_token"`
}

type ValidateTokenResponse struct {
	Valid  bool   `json:"valid"`
	UserID uint64 `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
}
