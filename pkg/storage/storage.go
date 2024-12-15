package storage

import (
	"database/sql"
	"time"
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

func (st *Storage) AddNewRefreshToken(id int, refreshToken []byte, expDate time.Time) error {
	_, err := st.DB.Exec("UPDATE auth SET refresh_id=$1, exp_date=$2 WHERE id=$3", refreshToken, expDate, id)
	if err != nil {
		return err
	}
	return nil
}

func (st *Storage) GetHashedRefreshTokenAndExpDate(id int) ([]byte, *time.Time, error) {
	var refreshID []byte
	expDate := new(time.Time)
	err := st.DB.QueryRow("SELECT refresh_id, exp_date FROM auth WHERE id=$1", id).Scan(&refreshID, expDate)
	if err != nil {
		return nil, nil, err
	}
	return refreshID, expDate, nil
}
