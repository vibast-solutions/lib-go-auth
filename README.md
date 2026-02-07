# auth-lib

Go client library for the Auth microservice, with REST and gRPC clients, a common interface, and Echo middleware.

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

## Notes

- gRPC types are imported from `github.com/vibast-solutions/ms-go-auth@v1.0.0`.
- REST methods send the `Authorization: Bearer <token>` header when needed.
