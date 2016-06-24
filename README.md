# goidc
Golang OpenID Connect Provider Framework (NOT STABLE YET)

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
    realm := "api.example.org"
    endpoint := goidc.NewTokenEndpoint(realm)
    endpoint.Support(grant.AuthorizationCode())
    endpoint.Support(grant.RefreshToken())

    di := my_data_interface.New()

    http.HandleFunc("/token", endpoint.Handler(di))
    http.ListenAndServe(":8080", nil)
}
```

1. Prepare **TokenEndpoint** with **NewTokenEndpoint** method
2. Specify GrantHandler for which grant_type you want to support.
3. Prepare **DataInterface** which is bridge to access to data stored in your service.
4. Finally, call **Handler**, passing the **DataInterface** you prepared.

**goidc**'s **TokenEndpoint** provides you a golang's **http.HandlerFunc** with it's **Handler** method.
So, it's easy to combine with your favorite Web Application Framework.

For instance, if you'd like to use [gin](https://github.com/gin-gonic/gin)

```go
g := gin.Default()
g.POST("/token", gin.WrapF(endpoint.Handler(di)))
```

## DataInterface


## ProtectedResource Endpoint

goidc provids ResourceProtector which supports
to check AccessToken validity on your API endpoint.

it has **Validate** method

Build a middleware according to your favorite Web Application Framework,
and in which, call **ResourceProtector**'s **Validate** method, like this.

```go
package main

import (
    "github.com/lyokato/goidc"
    "github.com/lyokato/goidc/grant"
    "github.com/gin-gonic/gin"
)

func main() {
    realm := "api.example.org"
    rp := goidc.NewResourceProtector(realm)

    di := my_data_interface.New()

    r := gin.Default()  

    r.Use(func(c *gin.Context){

        if rp.Validate(c.Writer, c.Request, di) {
            c.Next()
        } else {
            c.Abort()
        }
    })

    r.GET("/userinfo", my_controller.GetUserInfo)
    r.Run()
}
```

**my_controller** package example

```go
package my_controller

func GetUserInfo(c *gin.Context) {

  client_id := c.Request.Header("X-OAUTH-CLIENT-ID")
  scopes := c.Request.Header("X-OAUTH-SCOPE")

  uid_string := c.Request.Header("X-OAUTH-USER-ID")
  user_id, err := strconv.Atoi(uid_string)

  ...
}
```

So, it means, you can use ResourceProtector to check access token,
and if validation is succeeded, ResourceProtector put three values into HTTP header, 
and pass the request to handler matched to request url's path.

There are three headers

- X-OAUTH-USER-ID: user_id associated with the access_token
- X-OAUTH-CLIENT-ID: client_id associated with the access_token
- X-OAUTH-SCOPE: scope value associated with the access_token

And if token is invalid, ResourceProtector automatically returns error to client in proper manner.

### SCOPE VALIDATION

However, in this flow, ResourceProtector put the scope into header,
but doesn't confirm this scope matches the condition to access associated API endpoint(path).
You need to check it in your handler.

```go
package my_controller

func GetUserInfo(c *gin.Context) {

  client_id := c.Request.Header("X-OAUTH-CLIENT-ID")
  scopes := c.Request.Header("X-OAUTH-SCOPE")

  if !scopeIncludes(scopes, "profile") {
      // return error 
  }

  uid_string := c.Request.Header("X-OAUTH-USER-ID")
  user_id, err := strconv.Atoi(uid_string)

  ...
}
```

If you hope farther automated validation, There is **ValidateWithScopes** methods.

```go
pathScopeMap := map[string][]string {
  "/userinfo", []string{"profile", "email"},
  "/picture", []string{"picture"},
}

if rp.ValidateWithScopes(c.Writer, c.Request, di, pathScopeMap) {
    c.Next()
} else {
    c.Abort()
}

```

## JWK Endpoint

You can provide your public keys as **JWK** for **ID Token** signature easily with this feature.

For example, Google provides their JWK Here (https://www.googleapis.com/oauth2/v3/certs)

```go
package main

import (
    "github.com/lyokato/goidc"
    "github.com/lyokato/goidc/grant"
)

func main() {
    je := goidc.NewJWKEndpoint()

    // Add Text PEM
    je.AddFromText("my_key_id_1", `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)

    // or path of PEM file
    je.AddFromFile("my_pub_key_2", pemFilePath)

    http.HandleFunc("/cert", je.Handler())
    http.ListenAndServe(":8080", nil)
}
```


And it returns response like this.

```javascript
{
    "keys": [
        {
            "kid": "my_key_id_1",
            "kty": "RSA",
            "e": "AQAB",
            "n": "sxclFH1RsjAmxu2CMIKOF3ahI4YYCGSeCq-1SsCHOxfsdA6AZ4juroVOh1cTD4m8UgyBkCB6MT_RyTxhdV5RLexDMHsG-UXJLt96_tkAhE0ZkDMOvHmVGanbYMtSRQhbBVHDMHFXH06l1NNFBHrx_URQR6KsSbEQtJdcm3LOqNE"
        },
        {
            "kid": "my_key_id_2",
            "kty": "RSA",
            "e": "AQAB",
            "n": "sxclFH1RsjAmxu2CMIKOF3ahI4YYCGSeCq-1SsCHOxfsdA6AZ4juroVOh1cTD4m8UgyBkCB6MT_RyTxhdV5RLexDMHsG-UXJLt96_tkAhE0ZkDMOvHmVGanbYMtSRQhbBVHDMHFXH06l1NNFBHrx_URQR6KsSbEQtJdcm3LOqNE"
        }
    ]
}
```

## AuthorizationEndpoint

goidc also support features for AuthorizationEndpoint.
This is also **gin** example.
Prepare AuthorizationEndpoit with **goidc.NewAuthorizationEndpoint**, 
And call **HandleRequest**, **CompleteRequest**, **CancelRequest**,
with object which implements **AuthorizationCallbacks** interface

```go 
policy := authorization.DefaultPolicy()
policy.MaxMaxAge = 60
policy.MinMaxAge = 60
policy.IdTokenExpiresIn = 3600
policy.ConsentOmissionPeriod = 3600
policy.AuthSessionExpiresIn = 60

di := my_data_interface.New()
ai := goidc.NewAuthorizationEndpoint(di, policy)

r.GET("/authorize", func(c *gin.Context) {
  ai.HandleRequest(c.Writer, c.Request,
    my_authorization_callbaskc.New(c))
})
r.POST("/authorize", func(c *gin.Context) {
  ai.HandleRequest(c.Writer, c.Request,
    my_authorization_callbaskc.New(c))
})
r.POST("/authorized", func(c *gin.Context) {
  ai.CompleteRequest(c.Writer, c.Request,
    my_authorization_callbaskc.New(c))
})

r.POST("/unauthorized", func(c *gin.Context) {
  ai.CancelRequest(c.Writer, c.Request,
    my_authorization_callbaskc.New(c))
})
```
