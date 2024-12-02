package main

import (
	"AuthApp/config"
	"AuthApp/pkg/auth"
	"AuthApp/pkg/sender"
	"AuthApp/pkg/storage"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	cfg, err := config.GetConfig()

	if err != nil {
		log.Fatalf("get config error: [%s]\n", err.Error())
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=disable",
		cfg.DBusername,
		cfg.DBpassword,
		cfg.DBhost,
		cfg.DBname,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open sql connect failed, error: [%s]\n", err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("db ping failed, error: [%s]\n", err.Error())
	}

	authHandler := &auth.AuthHandler{
		Storage:     storage.NewStorage(db),
		Keys:        auth.NewKeys(),
		EmailSender: sender.NewEmailSenderServer(),
	}

	http.HandleFunc("GET /api/auth", authHandler.Issue)
	http.HandleFunc("GET /api/refresh", authHandler.Refresh)

	http.ListenAndServe(":"+cfg.HTTPport, nil)
}
