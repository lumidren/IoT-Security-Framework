# syntax=docker/dockerfile:1.7
# pki-init: pkictl (built from services/pki) on a minimal shell image for the compose dev PKI.
# Build context: the repository root (docker-compose.yml sets it).
FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
COPY services/pki/go.mod services/pki/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY services/pki/ ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/pkictl ./cmd/pkictl

FROM alpine:3.20
LABEL org.opencontainers.image.title="ironmesh-pki-init" \
      org.opencontainers.image.description="Development PKI bootstrap for the IronMesh compose stack" \
      org.opencontainers.image.source="https://github.com/lumidren/IoT-Security-Framework"
RUN apk add --no-cache openssl \
 && addgroup -S -g 10001 ironmesh \
 && adduser -S -D -H -u 10001 -G ironmesh -s /sbin/nologin ironmesh
COPY --from=build /out/pkictl /usr/local/bin/pkictl
COPY deploy/docker/pki-init/pki-init.sh /usr/local/bin/pki-init.sh
USER 10001:10001
ENTRYPOINT ["/bin/sh", "/usr/local/bin/pki-init.sh"]
