package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/vibast-solutions/lib-go-auth/client"
	"github.com/vibast-solutions/lib-go-auth/service"
)

type stubInternalEchoClient struct {
	resp client.InternalAccessResponse
	err  error
}

func (s *stubInternalEchoClient) ValidateInternalAccess(context.Context, client.InternalAccessRequest) (client.InternalAccessResponse, error) {
	return s.resp, s.err
}

func TestRequireInternalAuth_MissingHeader(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalEchoClient{})
	mw := NewEchoInternalAuthMiddleware(internalSvc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := mw.RequireInternalAuth(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireInternalAuth_SetsContext(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalEchoClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"auth", "notifications"},
		},
	})
	mw := NewEchoInternalAuthMiddleware(internalSvc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "key")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := mw.RequireInternalAuth(func(c echo.Context) error {
		serviceName, err := CallerServiceFromContext(c)
		if err != nil {
			t.Fatalf("expected caller service in context: %v", err)
		}
		if serviceName != "profile-service" {
			t.Fatalf("unexpected caller service %q", serviceName)
		}
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireInternalAccess_Denied(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalEchoClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"auth"},
		},
	})
	mw := NewEchoInternalAuthMiddleware(internalSvc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "key")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := mw.RequireInternalAccess("notifications")(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestProtectAllWithAccess_AppliesToGroup(t *testing.T) {
	internalSvc := service.NewInternalAuthService(&stubInternalEchoClient{
		resp: client.InternalAccessResponse{
			ServiceName:   "profile-service",
			AllowedAccess: []string{"notifications"},
		},
	})
	mw := NewEchoInternalAuthMiddleware(internalSvc)

	e := echo.New()
	g := e.Group("/internal")
	mw.ProtectAllWithAccess(g, "notifications")
	g.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/internal/ping", nil)
	req.Header.Set("X-API-Key", "key")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
