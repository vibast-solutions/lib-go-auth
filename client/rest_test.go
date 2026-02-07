package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRESTClient_BaseURLValidation(t *testing.T) {
	if _, err := NewRESTClient(""); err == nil {
		t.Fatalf("expected error for empty baseURL")
	}
	if _, err := NewRESTClient("http://[::1"); err == nil {
		t.Fatalf("expected error for invalid baseURL")
	}
}

func TestRESTClient_Logout_SendsAuthHeader(t *testing.T) {
	var gotAuth string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		_ = json.NewEncoder(w).Encode(LogoutResponse{Message: "ok"})
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	_, err = client.Logout(context.Background(), LogoutRequest{
		AccessToken:  "token",
		RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("expected auth header, got %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"refresh_token":"refresh"`) {
		t.Fatalf("expected refresh_token in body, got %s", gotBody)
	}
}

func TestRESTClient_ChangePassword_SendsAuthHeader(t *testing.T) {
	var gotAuth string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		_ = json.NewEncoder(w).Encode(ChangePasswordResponse{Message: "ok"})
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	_, err = client.ChangePassword(context.Background(), ChangePasswordRequest{
		AccessToken: "token",
		OldPassword: "old",
		NewPassword: "new",
	})
	if err != nil {
		t.Fatalf("change password failed: %v", err)
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("expected auth header, got %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"old_password":"old"`) || !strings.Contains(gotBody, `"new_password":"new"`) {
		t.Fatalf("expected passwords in body, got %s", gotBody)
	}
}

func TestRESTClient_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad"}`))
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	_, err = client.Login(context.Background(), LoginRequest{Email: "a", Password: "b"})
	if err == nil {
		t.Fatalf("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Body, "bad") {
		t.Fatalf("expected error body, got %s", apiErr.Body)
	}
}

func TestRESTClient_ResponseParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(LoginResponse{
			AccessToken:  "a",
			RefreshToken: "b",
			ExpiresIn:    60,
		})
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	res, err := client.Login(context.Background(), LoginRequest{Email: "a", Password: "b"})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if res.AccessToken != "a" || res.RefreshToken != "b" || res.ExpiresIn != 60 {
		t.Fatalf("unexpected login response: %+v", res)
	}
}

func TestRESTClient_RequestSerialization(t *testing.T) {
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"ok"}`))
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	_, err = client.ConfirmAccount(context.Background(), ConfirmAccountRequest{Token: "token"})
	if err != nil {
		t.Fatalf("confirm failed: %v", err)
	}

	if !strings.Contains(gotBody, `"token":"token"`) {
		t.Fatalf("expected token in body, got %s", gotBody)
	}
}

func TestRESTClient_Register(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/register" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(RegisterResponse{UserID: 1, Email: "user@example.com"})
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	res, err := client.Register(context.Background(), RegisterRequest{Email: "user@example.com", Password: "pass"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if res.UserID != 1 || res.Email != "user@example.com" {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestRESTClient_RefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/refresh-token" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(RefreshTokenResponse{AccessToken: "a", RefreshToken: "b", ExpiresIn: 10})
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	res, err := client.RefreshToken(context.Background(), RefreshTokenRequest{RefreshToken: "r"})
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if res.AccessToken != "a" || res.RefreshToken != "b" || res.ExpiresIn != 10 {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestRESTClient_GenerateConfirmToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/generate-confirm-token" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(GenerateConfirmTokenResponse{ConfirmToken: "t"})
	}))
	defer server.Close()

	client, err := NewRESTClient(server.URL)
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	res, err := client.GenerateConfirmToken(context.Background(), GenerateConfirmTokenRequest{Email: "user@example.com"})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if res.ConfirmToken != "t" {
		t.Fatalf("unexpected response: %+v", res)
	}
}
