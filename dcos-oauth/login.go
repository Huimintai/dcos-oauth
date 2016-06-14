package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dcos/dcos-oauth/common"
	"golang.org/x/net/context"

	"github.com/coreos/go-oidc/jose"
	"github.com/qiujian16/golang-client/identity/v3"
)

type loginRequest struct {
	Uid string `json:"uid,omitempty"`

	Password string `json:"password,omitempty"`

	Token string `json:"token,omitempty"`
}

type loginResponse struct {
	Token string `json:"token,omitempty"`
}

var url string

func handleLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	var lr loginRequest
	err := json.NewDecoder(r.Body).Decode(&lr)
	if err != nil {
		log.Printf("Decode: %v", err)
		return common.NewHttpError("JSON decode error", http.StatusBadRequest)
	}

	// Authenticate with just a username and password. The returned token is
	// unscoped to a tenant.

	//	url = "http://9.21.62.241:5000/v3"
	keyStoneURL, _ := ctx.Value("keyStoneURL").(string)
	creds := keystonev3.AuthOpts{
		AuthUrl:  keyStoneURL,
		Username: lr.Uid,
		Password: lr.Password,
		Project:  lr.Uid,
	}
	auth, token, err := keystonev3.DoAuthRequest(creds)
	if err != nil {
		fmt.Println("Error authenticating username/password:", err)
		return nil
	}
	if !auth.GetExpiration().After(time.Now()) {
		fmt.Println("There was an error. The auth token has an invalid expiration.")
		return nil
	}

	claims := jose.Claims{}
	claims.Add("uid", lr.Uid)
	claims.Add("token", token)
	secretKey, _ := ctx.Value("secret-key").([]byte)
	clusterToken, err := jose.NewSignedJWT(claims, jose.NewSignerHMAC("secret", secretKey))
	if err != nil {
		return common.NewHttpError("JWT creation error", http.StatusInternalServerError)
	}
	encodedClusterToken := clusterToken.Encode()

	const cookieMaxAge = 388800
	// required for IE 6, 7 and 8
	expiresTime := time.Now().Add(cookieMaxAge * time.Second)

	authCookie := &http.Cookie{
		Name:     "dcos-acs-auth-cookie",
		Value:    encodedClusterToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiresTime,
		MaxAge:   cookieMaxAge,
	}
	http.SetCookie(w, authCookie)

	user := User{
		Uid:         lr.Uid,
		Description: lr.Uid,
		IsRemote:    false,
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		log.Printf("Marshal: %v", err)
		return common.NewHttpError("JSON marshalling failed", http.StatusInternalServerError)
	}
	infoCookie := &http.Cookie{
		Name:    "dcos-acs-info-cookie",
		Value:   base64.URLEncoding.EncodeToString(userBytes),
		Path:    "/",
		Expires: expiresTime,
		MaxAge:  cookieMaxAge,
	}
	http.SetCookie(w, infoCookie)

	json.NewEncoder(w).Encode(loginResponse{Token: token})

	return nil
}
func handleLogout(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	// required for IE 6, 7 and 8
	expiresTime := time.Unix(1, 0)

	for _, name := range []string{"dcos-acs-auth-cookie", "dcos-acs-info-cookie"} {
		cookie := &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Expires:  expiresTime,
			MaxAge:   -1,
		}

		http.SetCookie(w, cookie)
	}

	return nil
}
