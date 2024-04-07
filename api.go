package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits int
	chirpCount     int
}

type userOutJSON struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type userWithToken struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
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
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		respondWithJSON(w, 200, chirps)
		return
	}

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

func PostChirpHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	if len([]rune(params.Body)) > 139 {
		respondWithError(w, 400, "Chirp is too long")
	} else {
		chirp, err := db.CreateChirp(cleanChirp(params.Body))
		if err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}
		respondWithJSON(w, 201, chirp)
	}
}

func GetUserHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	users, err := db.GetUsers()
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	userID := r.PathValue("userID")
	if userID == "" {
		respondWithJSON(w, 200, users)
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		log.Println(err)
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
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	hashPW, err := bcrypt.GenerateFromPassword([]byte(params.Password), 5)
	if err != nil {
		log.Printf("Error hashing parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	user, err := db.CreateUser(params.Email, hashPW)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	respondWithJSON(w, 201, userOutJSON{user.Id, user.Email})
}

func PutUserHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	authStr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authStr, "Bearer ") {
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

	userID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, 404, "ID not found")
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	if err = decoder.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	hashPW, err := bcrypt.GenerateFromPassword([]byte(params.Password), 5)
	if err != nil {
		log.Printf("Error hashing parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	user, err := db.UpdateUser(id, params.Email, hashPW)
	if err != nil {
		respondWithError(w, 500, fmt.Sprint(err))
	} else {
		respondWithJSON(w, 200, userOutJSON{user.Id, user.Email})
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request, db *database.DB, key string) {
	type parameters struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
	}

	users, err := db.GetUsers()
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	if err = decoder.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	id := -1
	for i, u := range users {
		if u.Email == params.Email {
			id = i
			break
		}
	}

	if id < 0 {
		respondWithError(w, 404, "User not found")
		return
	}

	// If expires_in_seconds not provided default to 24h
	secondsDay := 24 * 3600
	if params.ExpiresInSeconds == 0 || params.ExpiresInSeconds > secondsDay {
		params.ExpiresInSeconds = secondsDay
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:   "chirpy",
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(
				time.Duration(params.ExpiresInSeconds) * time.Second),
			),
			Subject: fmt.Sprint(id + 1),
		})

	strToken, err := token.SignedString([]byte(key))

	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	user := users[id]
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(params.Password))
	if err != nil {
		respondWithError(w, 401, "Wrong password")
	} else {
		respondWithJSON(w, 200, userWithToken{user.Id, user.Email, strToken})
	}
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	data, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
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
