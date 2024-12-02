package storage

import (
	"database/sql"
)

type Storage struct {
	DB *sql.DB
}

func NewStorage(db *sql.DB) *Storage {
	return &Storage{
		DB: db,
	}
}

func (st *Storage) CheckGUID(guid string) (int, error) {
	var id int
	err := st.DB.QueryRow("SELECT id FROM auth WHERE guid=$1", guid).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (st *Storage) AddNewRefreshID(id int, refreshID []byte) error {
	_, err := st.DB.Exec("UPDATE auth SET refresh_id=$1 WHERE id=$2", refreshID, id)
	if err != nil {
		return err
	}
	return nil
}

func (st *Storage) GetHashedRefreshID(id int) ([]byte, error) {
	var refreshID []byte
	err := st.DB.QueryRow("SELECT refresh_id FROM auth WHERE id=$1", id).Scan(&refreshID)
	if err != nil {
		return nil, err
	}
	return refreshID, nil
}
