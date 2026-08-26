# ---- build stage ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copy go.mod/go.sum first so `go mod download` is cached separately from
# source changes — editing app code won't re-download modules.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/cli-login-system ./cmd/cli

# ---- runtime stage ----
FROM alpine:3.20

# CA certs are needed if the app ever talks to anything over TLS
# (e.g. a managed Postgres with sslmode=require). Cheap to include now.
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Only the compiled binary and the migrations SQL files make it into the
# final image — no Go toolchain, no source.
COPY --from=builder /out/cli-login-system ./cli-login-system
COPY migrations ./migrations

ENTRYPOINT ["./cli-login-system"]
