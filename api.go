package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"chirpy/internal/database"
)

const accTokenDur = time.Hour           // 1 hour
const refTokenDur = 24 * 60 * time.Hour // 60 days

type apiConfig struct {
	fileserverHits int
	chirpCount     int
}

type userOutJSON struct {
	Id           int    `json:"id,omitempty"`
	Email        string `json:"email,omitempty"`
	AccessToken  string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

func (self *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (self *apiConfig) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<html>

    <body>
        <h1>Welcome, Chirpy Admin</h1>
        <p>Chirpy has been visited %d times!</p>
    </body>

</html>`, self.fileserverHits)))
}

func (self *apiConfig) resetHandler(w http.ResponseWriter, _ *http.Request) {
	self.fileserverHits = 0
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Number of server hits has been reset"))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func GetChirpHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	chirps, err := db.GetChirps()
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	sortOrder := r.URL.Query().Get("sort")
	if sortOrder == "desc" {
		slices.Reverse(chirps)
	}

	authorID := r.URL.Query().Get("author_id")
	if authorID == "" {
		respondWithJSON(w, 200, chirps)
		return
	}

	id, err := strconv.Atoi(authorID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	respondWithJSON(w, 200, slices.DeleteFunc(
		chirps,
		func(c database.Chirp) bool {
			return c.AuthorID != id
		},
	))
}

func GetChirpByIDHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	chirps, err := db.GetChirps()
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	chirpID := r.PathValue("chirpID")
	id, err := strconv.Atoi(chirpID)
	if err != nil {
		log.Println(err)
		return
	}

	if id > 0 && id <= len(chirps) {
		respondWithJSON(w, 200, chirps[id-1])
	} else {
		respondWithError(w, 404, "Chirp does not exist")
	}
}

func PostChirpHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error decoding parameters: %s", err))
		return
	}

	authorID, err := checkAuthentication(r, key)
	if err != nil {
		respondWithError(w, 401, fmt.Sprint(err))
	}

	if len([]rune(params.Body)) > 139 {
		respondWithError(w, 400, "Chirp is too long")
	} else {
		chirp, err := db.CreateChirp(cleanChirp(params.Body), authorID)
		if err != nil {
			respondWithError(w, 500, err.Error())
			return
		}
		respondWithJSON(w, 201, chirp)
	}
}

func DeleteChirpHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	authorID, err := checkAuthentication(r, key)
	if err != nil {
		respondWithError(w, 401, fmt.Sprint(err))
	}

	chirps, err := db.GetChirps()
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	id, err := strconv.Atoi(chirpID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	if id < 1 && id > len(chirps) {
		respondWithError(w, 404, "Chirp does not exist")
		return
	}

	chirpToDelete := chirps[id-1]
	if chirpToDelete.AuthorID == authorID {
		db.DeleteChirp(id - 1)
		respondWithJSON(w, 200, "Chirp successfully deleted")
	} else {
		respondWithError(w, 403, "Forbidden operation")
	}
}

func GetUserHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	users, err := db.GetUsers()
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	userID := r.PathValue("userID")
	if userID == "" {
		respondWithJSON(w, 200, users)
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	if id > 0 && id <= len(users) {
		respondWithJSON(w, 200, users[id-1])
	} else {
		respondWithError(w, 404, "User does not exist")
	}
}

func PostUserHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	hashPW, err := bcrypt.GenerateFromPassword([]byte(params.Password), 5)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	user, err := db.CreateUser(params.Email, hashPW)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	respondWithJSON(w, 201, userOutJSON{
		Id: user.Id, Email: user.Email, IsChirpyRed: user.IsChirpyRed},
	)
}

func checkAuthentication(r *http.Request, key string) (int, error) {
	authStr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authStr, "Bearer ") {
		return -1, errors.New("Invalid token")
	}

	// Strip "Bearer "
	tokenStr := authStr[7:]
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return -1, err
	}

	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return -1, err
	}
	if issuer != "chirpy-access" {
		return -1, errors.New("Invalid token")
	}

	userID, err := token.Claims.GetSubject()
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(userID)
}

func PutUserHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	id, err := checkAuthentication(r, key)
	if err != nil {
		respondWithError(w, 401, err.Error())
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	if err = decoder.Decode(&params); err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	hashPW, err := bcrypt.GenerateFromPassword([]byte(params.Password), 5)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	user, err := db.UpdateUser(id, params.Email, hashPW)
	if err != nil {
		respondWithError(w, 500, err.Error())
	} else {
		respondWithJSON(w, 200, userOutJSON{
			Id: user.Id, Email: user.Email, IsChirpyRed: user.IsChirpyRed},
		)
	}
}

func PostRefreshHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	authStr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authStr, "Bearer ") {
		respondWithError(w, 401, "Invalid token")
		return
	}

	// Strip "Bearer "
	tokenStr := authStr[7:]
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})

	if err != nil {
		log.Printf("Invalid token: %v\n", err)
		respondWithError(w, 401, "Invalid token")
		return
	}

	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithError(w, 404, "Issuer not found")
		return
	}
	if issuer != "chirpy-refresh" {
		respondWithError(w, 401, "Invalid token")
	}

	revokedTokens, err := db.GetRevokedTokens()
	if err != nil {
		respondWithError(w, 500, "Unavailable database")
		return
	}
	if _, ok := revokedTokens[tokenStr]; ok {
		respondWithError(w, 401, "Token was revoked")
		return
	}

	userID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, 404, "ID not found")
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	accessToken, err := getToken(id, accTokenDur, "chirpy-access", key)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	respondWithJSON(w, 200, userOutJSON{AccessToken: accessToken})

}

func PostRevokeHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	authStr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authStr, "Bearer ") {
		respondWithError(w, 401, "Invalid token")
		return
	}

	// Strip "Bearer "
	tokenStr := authStr[7:]
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})

	if err != nil {
		log.Printf("Invalid token: %v\n", err)
		respondWithError(w, 401, "Invalid token")
		return
	}

	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithError(w, 404, "Issuer not found")
		return
	}
	if issuer != "chirpy-refresh" {
		respondWithError(w, 401, "Invalid token")
	}

	err = db.RevokeToken(tokenStr)
	if err != nil {
		respondWithError(w, 500, "Database offline")
		return
	}
	respondWithJSON(w, 200, "Token revoked")
}

func LoginHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	type parameters struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
	}

	users, err := db.GetUsers()
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	if err = decoder.Decode(&params); err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	id := -1
	for i, u := range users {
		if u.Email == params.Email {
			id = i + 1
			break
		}
	}

	if id < 1 {
		respondWithError(w, 404, "User not found")
		return
	}

	accessToken, err := getToken(id, accTokenDur, "chirpy-access", key)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	refreshToken, err := getToken(id, refTokenDur, "chirpy-refresh", key)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	user := users[id-1]
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(params.Password))
	if err != nil {
		respondWithError(w, 401, "Wrong password")
	} else {
		respondWithJSON(w, 200, userOutJSON{
			user.Id, user.Email, accessToken, refreshToken, user.IsChirpyRed})
	}
}

func getToken(id int, duration time.Duration, issuer, key string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			Subject:   fmt.Sprint(id),
		})
	return token.SignedString([]byte(key))
}

func PostPolkaWeebhookHandler(w http.ResponseWriter, r *http.Request, db *database.DB, APIkey string) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
	}

	authStr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authStr, "ApiKey ") {
		respondWithError(w, 401, "Wrong API key")
		return
	}

	if authStr[7:] != APIkey {
		respondWithError(w, 401, "Wrong API key")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	if params.Event != "user.upgraded" {
		respondWithJSON(w, 200, "")
		return
	}

	err := db.UpgradeUser(params.Data.UserID)
	if errors.Is(err, database.UserNotFound) {
		respondWithError(w, 404, "User not found")
		return
	}
	if err != nil {
		respondWithError(w, 500, "")
		return
	}
	respondWithJSON(w, 200, "")
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	data, _ := json.Marshal(map[string]string{"error": msg})
	log.Println(msg)
	w.WriteHeader(code)
	w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
		return
	}
	w.WriteHeader(code)
	w.Write(data)
}

func cleanChirp(userInput string) string {
	filterWords := map[string]struct{}{"kerfuffle": {}, "sharbert": {}, "fornax": {}}
	out := []string{}
	for _, word := range strings.Split(userInput, " ") {
		if _, ok := filterWords[strings.ToLower(word)]; ok {
			out = append(out, "****")
		} else {
			out = append(out, word)
		}
	}
	return strings.Join(out, " ")
}
