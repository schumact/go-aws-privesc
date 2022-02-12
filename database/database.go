package database

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

type (
	Database interface {
		SelectData(string) string
		PutData(string) string // Performs an update or insert query
	}

	Sqlite struct {
		Db      *sql.DB
		outFile string
	}
)

// CreateDb returns a new Sqlite object
func CreateDb() *Sqlite {
	return &Sqlite{}
}

// SetFile sets an output file
func (s *Sqlite) SetFile() error {
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	fi, err := os.Create(filepath.Join(pwd, "output.txt"))
	if err != nil {
		return err
	}
	if err := fi.Close(); err != nil {
		return err
	}
	s.outFile = "output.txt"
	return nil
}

// OpenConn opens a database and initializes Sqlite.Db
func (s *Sqlite) OpenConn(dbName string) error {
	var err error
	s.Db, err = sql.Open("sqlite3", dbName)
	return err
}

// CloseConn closes an open database connection
func (s *Sqlite) CloseConn() error {
	return s.Db.Close()
}

// SelectData runs a select query
func (s *Sqlite) SelectData(query string) (*sql.Rows, error) {
	return s.Db.Query(query)
}

// PutData runs an insert or update query
func (s *Sqlite) PutData(query string) (sql.Result, error) {
	return s.Db.Exec(query)
}

// WriteText writes text to a Sqlite.OutFile. (Once I implement db, this can go)
func (s *Sqlite) WriteText(text string) error {
	fi, err := os.OpenFile(s.outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fi.Close()
	_, err = fi.WriteString(text)
	return err
}
