# syntax=docker/dockerfile:1.7
# Multi-stage build: static Go binaries on a distroless, non-root base image.

FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/pki ./cmd/pki && \
    go build -ldflags="-s -w" -o /out/pkictl ./cmd/pkictl

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="ironmesh-pki" \
      org.opencontainers.image.description="IronMesh Device PKI: EST with attestation, OCSP, CRL, management API" \
      org.opencontainers.image.source="https://github.com/lumidren/IoT-Security-Framework"
COPY --from=build /out/pki /usr/local/bin/pki
COPY --from=build /out/pkictl /usr/local/bin/pkictl
USER nonroot:nonroot
# 8443: EST + OCSP + management API (mTLS); 8444: CRL, metrics, health (plain)
EXPOSE 8443 8444
ENV PKI_LISTEN_MTLS=:8443 PKI_LISTEN_PLAIN=:8444 PKI_CA_DIR=/pki-data
VOLUME ["/pki-data"]
ENTRYPOINT ["/usr/local/bin/pki"]
