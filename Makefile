run:
	go run cmd/main.go

db:
	psql -p5432 -Uroot -dusersAuth
