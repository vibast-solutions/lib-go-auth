package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/vibast-solutions/lib-go-auth/service"
)

const (
	ContextKeyUserID    = "user_id"
	ContextKeyUserEmail = "user_email"
)

func UserIDFromContext(c echo.Context) (uint64, error) {
	v := c.Get(ContextKeyUserID)
	if v == nil {
		return 0, fmt.Errorf("user_id not found in context")
	}
	id, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("user_id has unexpected type %T", v)
	}
	return id, nil
}

func UserEmailFromContext(c echo.Context) (string, error) {
	v := c.Get(ContextKeyUserEmail)
	if v == nil {
		return "", fmt.Errorf("user_email not found in context")
	}
	email, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("user_email has unexpected type %T", v)
	}
	return email, nil
}

type EchoAuthMiddleware struct {
	authService *service.AuthService
}

func NewEchoAuthMiddleware(authService *service.AuthService) *EchoAuthMiddleware {
	return &EchoAuthMiddleware{authService: authService}
}

func (m *EchoAuthMiddleware) RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "missing authorization header",
			})
		}

		parts := strings.Fields(authHeader)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid authorization header format",
			})
		}

		userID, email, err := m.authService.Authenticate(c.Request().Context(), parts[1])
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired token",
			})
		}

		c.Set(ContextKeyUserID, userID)
		c.Set(ContextKeyUserEmail, email)
		return next(c)
	}
}
