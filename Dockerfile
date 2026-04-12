# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the open-democracy gateway. The first stage compiles
# the static Go binary; the second packages it into a tiny distroless image
# along with the embedded HTML/CSS assets (handled by go:embed at build time).
#
# Build:   docker build -t open-democracy-gateway .
# Run:     docker run --rm -p 8080:8080 -v od-data:/data open-democracy-gateway

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Cache modules separately so source-only edits don't refetch dependencies.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

# Build a fully-static binary so the runtime image can be distroless static.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/gateway /app/gateway

ENV GATEWAY_ADDR=:8080 \
    GATEWAY_DATA=/data \
    GATEWAY_USER=ada

VOLUME ["/data"]
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/app/gateway"]
