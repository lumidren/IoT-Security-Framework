GO        ?= go
BIN       ?= bin
PKG       := ./...
COVERFILE ?= coverage.out
IMAGE     ?= ironmesh/pki:dev

.PHONY: all build test test-race cover lint vet fmt tidy docker clean

all: fmt vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN)/pki ./cmd/pki
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN)/pkictl ./cmd/pkictl

## test: unit tests with the race detector and coverage (needs a C toolchain for -race)
test:
	$(GO) test $(PKG) -race -cover -coverprofile=$(COVERFILE) -covermode=atomic

## test-norace: same without the race detector (machines without cgo)
test-norace:
	$(GO) test $(PKG) -cover -coverprofile=$(COVERFILE)

## cover: per-package coverage summary plus an HTML report
cover: test
	$(GO) tool cover -func=$(COVERFILE) | tail -n 1
	$(GO) tool cover -html=$(COVERFILE) -o coverage.html

## integration: Postgres-backed store tests (set PKI_TEST_DATABASE_URL)
integration:
	$(GO) test ./internal/store/postgres/... -run TestPostgresConformance -v

## pkcs11: SoftHSM2-backed KMS tests (set SOFTHSM2_CONF, needs cgo)
pkcs11:
	$(GO) test -tags pkcs11 ./internal/kms/pkcs11/... -v

lint:
	golangci-lint run ./...

vet:
	$(GO) vet $(PKG)

fmt:
	gofmt -l -w .

tidy:
	$(GO) mod tidy

docker:
	docker build -t $(IMAGE) .

clean:
	rm -rf $(BIN) $(COVERFILE) coverage.html
