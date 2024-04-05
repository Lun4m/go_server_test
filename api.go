package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type apiConfig struct {
	fileserverHits int
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

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	w.Header().Set("Access-Control-Allow-Methods", "POST")

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	if len([]rune(params.Body)) > 139 {
		data, err := json.Marshal(map[string]string{"error": "Chirp is too long"})
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(400)
		w.Write(data)
	} else {
		data, err := json.Marshal(map[string]string{"cleaned_body": cleanChirp(params.Body)})
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.Write(data)
	}
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
