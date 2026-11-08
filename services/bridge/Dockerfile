# syntax=docker/dockerfile:1.7
# Build context: services/bridge (the module root). GOWORK=off keeps the build independent of
# the repository go.work so the image builds from this directory alone.
FROM golang:1.27-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/bridge ./cmd/bridge

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bridge /bridge
USER nonroot:nonroot
EXPOSE 8082
ENV BRIDGE_LISTEN=:8082
ENTRYPOINT ["/bridge"]
