package basic_auth

import (
	"encoding/base64"
	"net/http"
	"net/url"
)

func Token(uid, pass string) string {
	pair := url.QueryEscape(uid) + ":" + url.QueryEscape(pass)
	return base64.StdEncoding.EncodeToString([]byte(pair))
}

func Header(uid, pass string) string {
	return "Basic " + Token(uid, pass)
}

func FindClientCredential(r *http.Request) (string, string, bool) {
	cid, sec, exists := r.BasicAuth()
	if exists {
		return cid, sec, true
	}
	cid = r.FormValue("client_id")
	sec = r.FormValue("client_secret")
	if cid != "" && sec != "" {
		return cid, sec, true
	} else {
		return "", "", false
	}
}
