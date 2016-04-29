# goidc
Golang OpenID Connect Provider Framework

[![wercker status](https://app.wercker.com/status/1d1b23bfc5d6c80972e4b7aa66e8e6e4/m "wercker status")](https://app.wercker.com/project/bykey/1d1b23bfc5d6c80972e4b7aa66e8e6e4)

## TokenEndpoint


example:

```go
package main

import (
    "github.com/lyokato/goidc"
    "github.com/lyokato/goidc/grant"
)

func main() {

  endpoint := goidc.NewTokenEndpoint()
  endpoint.Support(grant.AuthorizationCode())
  endpoint.Support(grant.RefreshToken())

  sdi := my_service_dat_interface.New()

  http.HandleFunc("/token", endpoint.Handler(sdi))
  http.ListenAndServe(":8080", nil)
 }
```

1. Prepare TokenEndpoint with **NewTokenEndpoint** method
2. Specify GrantHandler for which grant_type you want to support.
3. Prepare **ServiceDataInterface** which is bridge to access to data stored in your service.
4. Finally, call **Handler**, passing the **ServiceDataInterface** you prepared.

goidc's TokenEndpoint provides you a golang's **http.HandlerFunc** with it's **Handler** method.
So, it's easy to combine with your favorite Web Application Framework.

For instance, if you like [gin](https://github.com/gin-gonic/gin)

```go
g := gin.Default()
g.POST("/token", gin.WrapF(endpoint.Handler(sdi)))
```

## ServiceDataInterface

### ClientInterface
### AuthInfoInterface
### AccessTokenInterface
### RefreshTokenInterface
