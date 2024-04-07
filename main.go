package main

import (
	// "fmt"
	"chirpy/internal/database"
	"flag"
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

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	mux := http.NewServeMux()

	config := apiConfig{}
	baseHandler := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))

	mux.Handle("/app/*", config.middlewareMetricsInc(baseHandler))

	db, err := database.NewDB(databasePath, *dbg)
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
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		GetChirpHandler(w, r, db)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		PostUserHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		GetUserHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		GetUserHandler(w, r, db)
	})

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		LoginHandler(w, r, db)
	})

	mux.HandleFunc("GET /api/reset", config.resetHandler)

	mux.HandleFunc("GET /admin/metrics", config.metricsHandler)

	corsMux := middlewareCors(mux)
	server := &http.Server{Addr: ":" + port, Handler: corsMux}
	log.Fatal(server.ListenAndServe())
}
