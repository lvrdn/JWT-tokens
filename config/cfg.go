package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPport   string
	DBhost     string
	DBname     string
	DBusername string
	DBpassword string
}

func GetConfig() (*Config, error) {
	file, err := os.Open("./config/app.env")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	env, err := godotenv.Parse(file)
	if err != nil {
		return nil, err
	}

	return &Config{
		HTTPport:   env["HTTP_PORT"],
		DBhost:     env["DB_HOST"],
		DBname:     env["DB_NAME"],
		DBusername: env["DB_USERNAME"],
		DBpassword: env["DB_PASSWORD"],
	}, nil
}
