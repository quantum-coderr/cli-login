# ---- build stage ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/cli-login-system ./cmd/cli

# ---- runtime stage ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /out/cli-login-system ./cli-login-system
COPY migrations ./migrations

ENTRYPOINT ["./cli-login-system"]
