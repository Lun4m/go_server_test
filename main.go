package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"chirpy/internal/database"
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

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")

	db, err := database.NewDB(databasePath, *dbg)
	if err != nil {
		log.Println(err)
	}

	config := apiConfig{}
	baseHandler := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))

	mux := http.NewServeMux()
	mux.Handle("/app/*", config.middlewareMetricsInc(baseHandler))

	// Chirps endpoint
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		PostChirpHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		GetChirpHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		GetChirpHandler(w, r, db)
	})

	// Users endpoint
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		PostUserHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		GetUserHandler(w, r, db)
	})
	mux.HandleFunc("GET /api/users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		GetUserHandler(w, r, db)
	})
	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		PutUserHandler(w, r, db, jwtSecret)
	})

	// Other api endpoints
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		LoginHandler(w, r, db, jwtSecret)
	})
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		PostRefreshHandler(w, r, db, jwtSecret)
	})
	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		PostRevokeHandler(w, r, db, jwtSecret)
	})
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /api/reset", config.resetHandler)

	mux.HandleFunc("GET /admin/metrics", config.metricsHandler)

	corsMux := middlewareCors(mux)
	server := &http.Server{Addr: ":" + port, Handler: corsMux}
	log.Fatal(server.ListenAndServe())
}
