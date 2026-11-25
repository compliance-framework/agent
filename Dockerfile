FROM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS builder
# Build with the go.mod toolchain line (Renovate bumps it for Go security fixes), downloading it when this image's Go is older.
ENV GOTOOLCHAIN=auto

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG VERSION=dev
# Static binary, as .goreleaser.yaml builds it: nothing in the agent needs cgo, and CCF's plugins are static too.
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o concom main.go

# distroless/static has no libc or libssl to patch (agent-action copies /app/concom out of this image).
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS final

WORKDIR /app
COPY --from=builder /app/concom /app/concom

CMD ["./concom", "agent", "-c", "/app/config.yml"]
