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
    realm := "api.example.org"
    endpoint := goidc.NewTokenEndpoint(realm)
    endpoint.Support(grant.AuthorizationCode())
    endpoint.Support(grant.RefreshToken())

    sdi := my_service_data_interface.New()

    http.HandleFunc("/token", endpoint.Handler(sdi))
    http.ListenAndServe(":8080", nil)
 }
```

1. Prepare **TokenEndpoint** with **NewTokenEndpoint** method
2. Specify GrantHandler for which grant_type you want to support.
3. Prepare **ServiceDataInterface** which is bridge to access to data stored in your service.
4. Finally, call **Handler**, passing the **ServiceDataInterface** you prepared.

**goidc**'s **TokenEndpoint** provides you a golang's **http.HandlerFunc** with it's **Handler** method.
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

## ProtectedResource Endpoint

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
