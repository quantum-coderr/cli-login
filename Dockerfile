# ---- build stage ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copying just go.mod and go.sum first means the module download layer
# only gets invalidated when dependencies change, not on every code edit.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/cli-login-system ./cmd/cli

# ---- runtime stage ----
# Using alpine here instead of a distroless image, on purpose. Distroless
# would give a smaller image and a slightly smaller attack surface, but it
# has no shell at all, and this project is still something you will want
# to poke at from inside the running container while working on it (a
# quick docker exec sh to check a file, look at env vars, whatever).
# Alpine keeps that possible for barely any extra size. If this ever
# became a real production image, distroless would be worth revisiting.
FROM alpine:3.20

# ca-certificates is here in case the app ever connects to Postgres with
# sslmode=require or talks to anything else over TLS. Not strictly needed
# for the default local setup, but cheap to have and avoids a surprise
# later if someone points DATABASE_URL at a hosted Postgres instance.
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Only the compiled binary and the migration SQL files are copied in.
# No source, no go.mod, no build cache, nothing the Go toolchain needed
# along the way.
COPY --from=builder /out/cli-login-system ./cli-login-system
COPY migrations ./migrations

# Exec form (JSON array) rather than shell form, so the binary runs as
# PID 1 directly instead of under a shell. That matters here because the
# CLI reads from stdin and handles Ctrl+C/Ctrl+D itself, and we want
# signals and terminal input going straight to it, not through an extra
# shell process in between.
ENTRYPOINT ["./cli-login-system"]
