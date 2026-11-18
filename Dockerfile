FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder
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
