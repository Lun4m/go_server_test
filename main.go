package main

import (
	// "fmt"
	"chirpy/internal/database"
	"log"
	"net/http"
)

func middlewareCors(next http.Handler) http.Handler {
	// Needed for validation
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	const filepathRoot = "."
	const port = "8080"
	const databasePath = "database.json"

	mux := http.NewServeMux()

	config := apiConfig{}
	baseHandler := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))

	mux.Handle("/app/*", config.middlewareMetricsInc(baseHandler))

	db, err := database.NewDB(databasePath)
	if err != nil {
		log.Println(err)
	}

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		PostChirpHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		GetChirpHandler(w, r, db)
	})

	mux.HandleFunc("GET /api/reset", config.resetHandler)

	mux.HandleFunc("GET /admin/metrics", config.metricsHandler)

	corsMux := middlewareCors(mux)
	server := &http.Server{Addr: ":" + port, Handler: corsMux}
	log.Fatal(server.ListenAndServe())
}
