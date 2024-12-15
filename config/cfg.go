package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPport         string
	DBhost           string
	DBname           string
	DBusername       string
	DBpassword       string
	AccessKey        string
	AccessExpMinutes int
	RefreshExpMonths int
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

	accessExpMinutes, err := strconv.Atoi(env["ACCESS_EXP_MINUTES"])
	if err != nil {
		return nil, fmt.Errorf(`error with parse config param "ACCESS_EXP_MINUTES", check config value must be int`)
	}

	refreshExpMonths, err := strconv.Atoi(env["REFRESH_EXP_MONTHS"])
	if err != nil {
		return nil, fmt.Errorf(`error with parse config param "REFRESH_EXP_MONTHS", check config value must be int`)
	}

	return &Config{
		HTTPport:         env["HTTP_PORT"],
		DBhost:           env["DB_HOST"],
		DBname:           env["DB_NAME"],
		DBusername:       env["DB_USERNAME"],
		DBpassword:       env["DB_PASSWORD"],
		AccessKey:        env["ACCESS_KEY"],
		AccessExpMinutes: accessExpMinutes,
		RefreshExpMonths: refreshExpMonths,
	}, nil
}
