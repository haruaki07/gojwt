package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cristalhq/jwt/v4"
)

type User struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserClaims struct {
	jwt.RegisteredClaims
	Uid      int    `json:"uid"`
	Username string `json:"username"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var JWT_KEY = []byte(`abcdeaosdqowiej`)
var JWT_EXPIRY = time.Duration(time.Second * 20)
var users = []User{
	{1, "john", "john"},
	{2, "mike", "mike"},
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", AuthLoginHandler)
	mux.HandleFunc("/api/auth/me", AuthMeHandler)
	mux.HandleFunc("/api/auth/refresh", AuthRefreshHandler)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)

	go func() {
		println("Listening on port 8000")
		err := http.ListenAndServe(":8000", mux)
		if err != nil {
			panic(err)
		}
	}()

	<-c
	println("Shutting down server")
}

func AuthRefreshHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	refreshTokenStr := r.Form.Get("refresh_token")
	if refreshTokenStr == "" {
		http.Error(w, "refresh_token is required!", http.StatusBadRequest)
		return
	}

	refreshToken, err := validateJwt(refreshTokenStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims := &UserClaims{}
	err = refreshToken.DecodeClaims(claims)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var user *User
	for _, u := range users {
		if u.Id == claims.Uid {
			user = &u
			break
		}
	}

	accessToken, err := generateAccessToken(*user)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(map[string]interface{}{
		"access_token": accessToken.String(),
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func AuthMeHandler(w http.ResponseWriter, r *http.Request) {
	authzHeader := r.Header.Get("Authorization")

	if authzHeader == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	jwtStr := getJwtFromHeader(authzHeader)
	if jwtStr == nil {
		http.Error(w, "invalid jwt", http.StatusUnauthorized)
		return
	}

	token, err := validateJwt(*jwtStr)
	if token == nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims := &UserClaims{}
	err = token.DecodeClaims(claims)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var user *User
	for _, u := range users {
		if u.Id == claims.Uid {
			user = &u
			break
		}
	}

	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	response, err := json.Marshal(map[string]interface{}{
		"user": user,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		http.Error(w, "username or password is required!", http.StatusBadRequest)
		return
	}

	var user *User
	for _, u := range users {
		if u.Username == username {
			user = &u
			break
		}
	}

	if user == nil || user.Password != password {
		http.Error(w, "username or password is wrong!", http.StatusBadRequest)
		return
	}

	tokens, err := generateTokens(*user)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(map[string]interface{}{
		"user":   user,
		"tokens": tokens,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func validateJwt(str string) (*jwt.Token, error) {
	verifier, err := jwt.NewVerifierHS(jwt.HS256, JWT_KEY)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse([]byte(str), verifier)
	if err != nil {
		return nil, err
	}

	claims := &UserClaims{}
	err = token.DecodeClaims(claims)
	if err != nil {
		return nil, err
	}

	if claims.ExpiresAt != nil && time.Now().UTC().Unix() >= claims.ExpiresAt.Unix() {
		return nil, errors.New("jwt expired")
	}

	if err = verifier.Verify(token); err != nil {
		return nil, err
	}

	return token, nil
}

func getJwtFromHeader(header string) *string {
	if !strings.HasPrefix(header, "Bearer ") {
		return nil
	}

	return &strings.Split(header, " ")[1]
}

func signJwt(claims interface{}) (*jwt.Token, error) {
	signer, err := jwt.NewSignerHS(jwt.HS256, JWT_KEY)
	if err != nil {
		return nil, err
	}

	return jwt.NewBuilder(signer).Build(claims)
}

func generateTokens(user User) (*Tokens, error) {
	accessToken, err := generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := signJwt(&UserClaims{
		jwt.RegisteredClaims{},
		user.Id,
		user.Username,
	})
	if err != nil {
		return nil, err
	}

	return &Tokens{accessToken.String(), refreshToken.String()}, nil
}

func generateAccessToken(user User) (*jwt.Token, error) {
	return signJwt(&UserClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_EXPIRY).UTC()),
		},
		user.Id,
		user.Username,
	})
}
