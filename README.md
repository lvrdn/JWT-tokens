# JWT-tokens

В данном проекте реализовано взаимодействие с access и refresh токенами:
1. маршрут "/api/auth" - создание пары access и refresh токенов;
2. маршрут "/api/refresh" - обновление пары access и refresh токенов;

База данных Postgresql поднимается в docker-контейнере с помощью docker-compose файла, таблица с необходимыми полями и вводными данными задается файлом ./migration/_init_table.sql.
Клиенту передаются: refresh токен в cookie, access token в body.
Серверу передаются: refresh токен в cookie, access token в header.

Для проверки работы авторизации был написан тест, в котором проверяется выдача токенов, получение ошибок:
```
$ go test -v
=== RUN   TestApp
--- PASS: TestApp (0.41s)
PASS
ok      AuthApp/test    0.671s
```

Для отправки warning email при обновлении пары refresh токена реализован интерфейс EmailSender:
```
2024/12/15 13:01:06 warning message succesfully sended to [some email]
2024/12/15 13:01:06 unknown ip get access to refresh operation: unknown ip: [127.0.0.1:49430], expected ip: [255.255.255.255], refresh id: [pO365Cknx9y3opl.x53JM]
```
