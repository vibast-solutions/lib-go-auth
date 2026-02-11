# auth-lib

Go client library for the Auth microservice, with REST and gRPC clients, a common interface, and Echo middleware.

Auth service expects trusted caller API key on every endpoint:
- HTTP header: `X-API-Key`
- gRPC metadata: `x-api-key`

`APP_API_KEY` is required. `auth-lib` reads this env var and attaches it automatically on every outgoing request.

## Install

```bash
go get github.com/vibast-solutions/lib-go-auth
```

## REST client

```go
restClient, err := client.NewRESTClient("http://localhost:8080")
if err != nil {
    // handle
}

login, err := restClient.Login(ctx, client.LoginRequest{
    Email:    "user@example.com",
    Password: "password",
})
```

## gRPC client

```go
grpcClient, err := client.NewGRPCClientFromAddr(ctx, "localhost:9090")
if err != nil {
    // handle
}
defer grpcClient.Close()
```

## Common interface

```go
var authClient client.AuthClient = restClient
```

## Echo middleware

```go
authSvc := service.NewAuthService(restClient)
mw := middleware.NewEchoAuthMiddleware(authSvc)

e := echo.New()
e.Use(mw.RequireAuth)
```

## Internal service-to-service auth (HTTP routes)

```go
restClient, _ := client.NewRESTClient("http://localhost:8080")
internalSvc := service.NewInternalAuthService(restClient)
internalMW := middleware.NewEchoInternalAuthMiddleware(internalSvc)

e := echo.New()

// Protect all routes in a group (easy mode)
internal := e.Group("/internal")
internalMW.ProtectAllWithAccess(internal, "profile-service")
internal.GET("/ping", pingHandler)

// Or protect specific routes only
e.GET("/health", healthHandler) // public
e.GET("/secure", secureHandler, internalMW.RequireInternalAccess("profile-service"))
```

The middleware reads caller `X-API-Key` from incoming request and calls Auth `POST /auth/internal/access` with:
- caller key in request header (`X-API-Key`) from `APP_API_KEY`
- inspected key in JSON body (`api_key`) from incoming request

It injects caller info in Echo context:
- `caller_service`
- `caller_allowed_access`

## Internal service-to-service auth (gRPC / protobuf)

```go
restClient, _ := client.NewRESTClient("http://localhost:8080")
internalSvc := service.NewInternalAuthService(restClient)
grpcMW := middleware.NewGRPCInternalAuthMiddleware(internalSvc)

server := grpc.NewServer(
    grpc.UnaryInterceptor(grpcMW.UnaryRequireInternalAccess("profile-service")),
)
```

Selective protection for only specific protobuf methods:

```go
server := grpc.NewServer(
    grpc.UnaryInterceptor(
        grpcMW.UnaryRequireInternalAccessFor(
            "profile-service",
            "/profile.ProfileService/UpdateProfile",
            "/profile.ProfileService/DeleteProfile",
        ),
    ),
)
```

The gRPC interceptor reads incoming metadata key `x-api-key` and stores caller info in context helpers:
- `middleware.CallerServiceFromGRPCContext(ctx)`
- `middleware.CallerAllowedAccessFromGRPCContext(ctx)`

`NewInternalAuthService` works with either:
- REST client (`NewRESTClient`) calling `POST /auth/internal/access`
- gRPC client (`NewGRPCClient`) calling `ValidateInternalAccess`

## Notes

- gRPC types are imported from `github.com/vibast-solutions/ms-go-auth@v1.0.3`.
- REST methods always send `X-API-Key` from `APP_API_KEY`.
- gRPC methods always send `x-api-key` metadata from `APP_API_KEY`.
