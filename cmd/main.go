package main

import (
	"AuthApp/config"
	"AuthApp/pkg/auth"
	"AuthApp/pkg/sender"
	"AuthApp/pkg/storage"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"
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
		AccessKey:        cfg.AccessKey,
		AccessExpMinutes: cfg.AccessExpMinutes,
		RefreshExpMonths: cfg.RefreshExpMonths,
		Storage:          storage.NewStorage(db),
		EmailSender:      sender.NewEmailSenderServer(),
	}

	http.HandleFunc("GET /api/auth", authHandler.Issue)
	http.HandleFunc("GET /api/refresh", authHandler.Refresh)

	server := http.Server{
		Addr: ":" + cfg.HTTPport,
	}

	go func() {
		server.ListenAndServe()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c

	server.Shutdown(context.Background())
	fmt.Println("Server stopped")
}
