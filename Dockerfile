FROM golang:1.26.1 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# The shared release workflows pass no build args. Without VERSION, the release tag checked
# out at HEAD (vX.Y.Z or vX.Y.Z-rcN) sets it, without the "v", as the old VERSION arg did.
ARG VERSION=
RUN if [ -z "$VERSION" ]; then \
      VERSION="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null)" && VERSION="${VERSION#v}" || VERSION=dev; \
    fi; \
    go build -ldflags "-X main.version=${VERSION}" -o concom main.go

FROM gcr.io/distroless/base-debian12 AS final

WORKDIR /app
COPY --from=builder /app/concom /app/concom

CMD ["./concom", "agent", "-c", "/app/config.yml"]
