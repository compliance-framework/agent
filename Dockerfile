FROM golang:1.23.2 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o concom main.go

FROM gcr.io/distroless/base-debian12 AS final

WORKDIR /app
COPY --from=builder /app/concom /app/concom

ENTRYPOINT ["/app/concom"]
