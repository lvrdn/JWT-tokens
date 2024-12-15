DROP TABLE IF EXISTS "auth";
CREATE TABLE auth (
    "id" serial PRIMARY KEY,
    "guid" uuid NOT NULL,
    "refresh_id"  bytea,
    "exp_date" date
);

INSERT INTO "auth" ("id", "guid") VALUES
(1,'da92d676-1fa8-479f-84ac-68e0a6f0460f');