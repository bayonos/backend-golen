# backend-go

Go port of the BunJS login and authentication backend (`smartfarm_db` / MySQL). Standard library HTTP server with MySQL and SQLite storage, JWT access tokens, rotating refresh tokens, and rate-limited login.

## Run

```bash
JWT_SECRET="replace-with-a-long-random-secret" go run ./cmd/server
```

Or build and run:

```bash
go build -o server ./cmd/server
./server
```

## Configuration

Environment variables (local `.env` is loaded but real environment variables win):

- `HOST` (default `0.0.0.0`), `PORT` (default `8080`)
- `DATABASE_URL` — `mysql://user:password@host:3306/smartfarm_db` or `sqlite://auth.db`
- `DB_DRIVER` / `DB_CONNECTION` — `mysql` (default) or `sqlite`
- `DB_PATH` — SQLite path (default `auth.db`)
- `MYSQL_HOST` / `DB_HOST` (default `127.0.0.1`)
- `MYSQL_PORT` / `DB_PORT` (default `3306`)
- `MYSQL_USER` / `DB_USER` / `DB_USERNAME` (default `root`)
- `MYSQL_PASSWORD` / `DB_PASSWORD` (default `root`)
- `MYSQL_DB` / `DB_DATABASE` / `DB_NAME` (default `smartfarm_db`)
- `JWT_SECRET` — set a strong persistent secret in production; a random ephemeral one is generated otherwise
- `ACCESS_TOKEN_TTL_SEC` (default `900`)
- `REFRESH_TOKEN_TTL_SEC` (default `604800`)
- `PBKDF2_ITERATIONS` (default `210000`)
- `LOGIN_MAX_ATTEMPTS` (default `10`)
- `LOGIN_RATE_WINDOW_SEC` (default `60`)

## Users table

Matches `smartfarm_db.users`: `id`, `username`, `password`, `full_name`, `email`, `phone`, `role`, `status`, `created_at`.

- New passwords use PBKDF2-HMAC-SHA256 (`210000` iterations, 16-byte salt).
- Legacy plaintext passwords already in MySQL are supported via constant-time comparison.
- Accounts with `status != 'active'` are rejected with `403`.
- Refresh tokens are stored SHA-256 hashed in `smartfarm_db.refresh_tokens`, created automatically on startup.

## Tests

```bash
go test ./...
bash scripts/smoke_test.sh
```

The smoke test requires a local MySQL `smartfarm_db` with `root`/`root` credentials.

## API endpoints

- `GET /`
- `GET /health` (and `/healthz`)
- `POST /api/auth/register` (alias `/auth/register`) — `{ "username", "password", "full_name"?, "email"?, "phone"?, "role"? }`
- `POST /api/auth/login` (alias `/auth/login`) — `{ "username" | "email" | "identifier", "password" }`
- `POST /api/auth/refresh` (alias `/auth/refresh`) — `{ "refresh_token" }`
- `POST /api/auth/logout` (alias `/auth/logout`) — `{ "refresh_token" }`
- `POST /api/auth/logout-all` (alias `/auth/logout-all`) — `Authorization: Bearer <access_token>`
- `GET /api/auth/me` (alias `/auth/me`) — `Authorization: Bearer <access_token>`
- `POST /api/auth/change-password` (alias `/auth/change-password`) — `Authorization: Bearer <access_token>`, `{ "current_password", "new_password" }`

# backend-golen
