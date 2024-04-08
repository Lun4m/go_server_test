package database

import (
	"encoding/json"
	"errors"
	_ "log"
	"os"
	"sync"
	"time"
)

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps        map[int]Chirp        `json:"chirps"`
	Users         map[int]User         `json:"users"`
	RevokedTokens map[string]time.Time `json:"revoked_tokens"`
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorID int    `json:"author_id"`
}

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password []byte `json:"password"`
}

func NewDB(path string, dbg bool) (*DB, error) {
	if _, err := os.ReadFile(path); dbg || errors.Is(err, os.ErrNotExist) {
		os.Create(path)
	}
	return &DB{path: path, mu: &sync.RWMutex{}}, nil
}

func (self *DB) CreateChirp(body string, authorID int) (Chirp, error) {
	db, err := self.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(db.Chirps) + 1
	chirp := Chirp{Id: id, Body: body, AuthorID: authorID}
	db.Chirps[id] = chirp

	err = self.writeDB(db)
	if err != nil {
		return Chirp{}, err
	}
	return chirp, nil
}

func (self *DB) DeleteChirp(chirpID int) error {
	db, err := self.loadDB()
	if err != nil {
		return err
	}

	delete(db.Chirps, chirpID)

	err = self.writeDB(db)
	if err != nil {
		return err
	}
	return nil
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

func (self *DB) CreateUser(email string, pw []byte) (User, error) {
	db, err := self.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, u := range db.Users {
		if u.Email == email {
			return User{}, errors.New("User with the given email already exists")
		}
	}

	id := len(db.Users) + 1

	user := User{Id: id, Email: email, Password: pw}
	db.Users[id] = user

	err = self.writeDB(db)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (self *DB) UpdateUser(id int, email string, pw []byte) (User, error) {
	db, err := self.loadDB()
	if err != nil {
		return User{}, err
	}

	user := User{Id: id, Email: email, Password: pw}
	db.Users[id] = user

	err = self.writeDB(db)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (self *DB) GetUsers() ([]User, error) {
	db, err := self.loadDB()
	if err != nil {
		return nil, err
	}

	users := make([]User, len(db.Users))
	for i := 1; i <= len(db.Users); i++ {
		users[i-1] = db.Users[i]
	}

	return users, nil
}

func (self *DB) RevokeToken(token string) error {
	db, err := self.loadDB()
	if err != nil {
		return err
	}

	db.RevokedTokens[token] = time.Now()

	err = self.writeDB(db)
	if err != nil {
		return err
	}
	return nil
}

func (self *DB) GetRevokedTokens() (map[string]time.Time, error) {
	db, err := self.loadDB()
	if err != nil {
		return nil, err
	}
	return db.RevokedTokens, nil
}

func (self *DB) loadDB() (DBStructure, error) {
	db := DBStructure{
		Chirps:        make(map[int]Chirp),
		Users:         make(map[int]User),
		RevokedTokens: make(map[string]time.Time),
	}

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
