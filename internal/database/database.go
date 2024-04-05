package database

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
}

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

func NewDB(path string) (*DB, error) {
	if _, err := os.ReadFile(path); errors.Is(err, os.ErrNotExist) {
		os.Create(path)
	}
	return &DB{path: path, mu: &sync.RWMutex{}}, nil
}

func (self *DB) CreateChirp(body string) (Chirp, error) {
	db, err := self.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(db.Chirps) + 1
	chirp := Chirp{Id: id, Body: body}
	db.Chirps[id] = chirp

	err = self.writeDB(db)
	if err != nil {
		return Chirp{}, err
	}
	return chirp, nil
}

func (self *DB) GetChirps() ([]Chirp, error) {
	db, err := self.loadDB()
	if err != nil {
		return nil, err
	}

	chirps := make([]Chirp, len(db.Chirps))
	for i := 1; i <= len(db.Chirps); i++ {
		chirps[i-1] = db.Chirps[i]
	}

	return chirps, nil
}

func (self *DB) loadDB() (DBStructure, error) {
	db := DBStructure{Chirps: make(map[int]Chirp)}

	self.mu.RLock()
	defer self.mu.RUnlock()

	file, err := os.ReadFile(self.path)
	if err != nil {
		return db, err
	}

	// Check if file is empty
	if len(file) == 0 {
		return db, nil
	}

	err = json.Unmarshal(file, &db)
	if err != nil {
		return db, err
	}
	return db, nil
}

func (self *DB) writeDB(db DBStructure) error {
	data, err := json.Marshal(db)
	if err != nil {
		return err
	}

	self.mu.Lock()
	defer self.mu.Unlock()

	if err = os.WriteFile(self.path, data, 0666); err != nil {
		return err
	}
	return nil
}
