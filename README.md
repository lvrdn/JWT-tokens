# JWT-tokens

В данном проекте реализовано взаимодействие с access и refresh токенами:
1. маршрут "/api/auth" - создание пары access и refresh токенов;
2. маршрут "/api/refresh" - обновление пары access и refresh токенов при валидном refresh токене.

База данных Postgresql поднимается в docker-контейнере с помощью docker-compose файла, таблица с необходимыми полями и вводными данными задается файлом ./migration/_init_table.sql.
Токены передаются в cookie на сервер и с сервера.

Для проверки работы авторизации был написан тест, в котором проверяется выдача токенов, получение ошибок:
```
$ go test -v
=== RUN   TestApp
--- PASS: TestApp (0.47s)
PASS
ok      AuthApp/test    0.734s
```

Для отправки warning email при обновлении пары refresh токена реализован интерфейс EmailSender:
```
2024/12/02 09:49:50 warning msg succesfully sended to [some email]
2024/12/02 09:49:50 unknown ip get access to refresh operation: unknown ip: [127.0.0.1:50728], expected ip: [255.255.255.255], refresh id: [0f29cfc8-84cd-4445-9b46-fecbc7814bd1]
```
