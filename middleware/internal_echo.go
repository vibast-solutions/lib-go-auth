package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/vibast-solutions/lib-go-auth/service"
)

const (
	ContextKeyCallerService       = "caller_service"
	ContextKeyCallerAllowedAccess = "caller_allowed_access"
)

func CallerServiceFromContext(c echo.Context) (string, error) {
	v := c.Get(ContextKeyCallerService)
	if v == nil {
		return "", fmt.Errorf("caller_service not found in context")
	}
	serviceName, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("caller_service has unexpected type %T", v)
	}
	return serviceName, nil
}

func CallerAllowedAccessFromContext(c echo.Context) ([]string, error) {
	v := c.Get(ContextKeyCallerAllowedAccess)
	if v == nil {
		return nil, fmt.Errorf("caller_allowed_access not found in context")
	}
	allowed, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("caller_allowed_access has unexpected type %T", v)
	}
	return allowed, nil
}

type EchoInternalAuthMiddleware struct {
	authService *service.InternalAuthService
}

func NewEchoInternalAuthMiddleware(authService *service.InternalAuthService) *EchoInternalAuthMiddleware {
	return &EchoInternalAuthMiddleware{authService: authService}
}

func (m *EchoInternalAuthMiddleware) RequireInternalAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		apiKey := strings.TrimSpace(c.Request().Header.Get("X-API-Key"))
		if apiKey == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "missing x-api-key header",
			})
		}

		serviceName, allowedAccess, err := m.authService.AuthenticateInternal(c.Request().Context(), apiKey)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired api key",
			})
		}

		c.Set(ContextKeyCallerService, serviceName)
		c.Set(ContextKeyCallerAllowedAccess, allowedAccess)

		return next(c)
	}
}

func (m *EchoInternalAuthMiddleware) RequireInternalAccess(targetService string) echo.MiddlewareFunc {
	targetService = strings.TrimSpace(targetService)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := strings.TrimSpace(c.Request().Header.Get("X-API-Key"))
			if apiKey == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "missing x-api-key header",
				})
			}

			resp, err := m.authService.AuthorizeInternal(c.Request().Context(), apiKey, targetService)
			if err != nil {
				if errors.Is(err, service.ErrInternalAPIDenied) {
					return c.JSON(http.StatusForbidden, map[string]string{
						"error": "forbidden",
					})
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid or expired api key",
				})
			}

			c.Set(ContextKeyCallerService, resp.ServiceName)
			c.Set(ContextKeyCallerAllowedAccess, resp.AllowedAccess)

			return next(c)
		}
	}
}

func (m *EchoInternalAuthMiddleware) ProtectAll(group *echo.Group) {
	group.Use(m.RequireInternalAuth)
}

func (m *EchoInternalAuthMiddleware) ProtectAllWithAccess(group *echo.Group, targetService string) {
	group.Use(m.RequireInternalAccess(targetService))
}
