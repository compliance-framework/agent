FROM golang:1.26.1 AS builder
# Build with the go.mod toolchain line (Renovate bumps it for Go security fixes), downloading it when this image's Go is older.
ENV GOTOOLCHAIN=auto

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG VERSION=dev
RUN go build -ldflags "-X main.version=${VERSION}" -o concom main.go

FROM gcr.io/distroless/base-debian12 AS final

WORKDIR /app
COPY --from=builder /app/concom /app/concom

CMD ["./concom", "agent", "-c", "/app/config.yml"]
