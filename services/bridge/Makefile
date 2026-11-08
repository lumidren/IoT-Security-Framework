GO      ?= go
PKG     := ./...
BIN     := bin/bridge
IMAGE   ?= ironmesh/bridge:dev
COVER   := coverage.out

.PHONY: all build run test test-race cover vet fmt fmt-check lint docker clean

all: fmt-check vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/bridge

run: build
	./$(BIN)

test:
	$(GO) test $(PKG) -cover

## Race detector needs cgo on Windows; on Linux/macOS it runs without extra tooling.
test-race:
	$(GO) test $(PKG) -race -cover

cover:
	$(GO) test ./internal/... -coverprofile=$(COVER) -covermode=atomic
	$(GO) tool cover -func=$(COVER) | tail -1

vet:
	$(GO) vet $(PKG)

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check vet

docker:
	docker build -t $(IMAGE) .

clean:
	rm -rf bin $(COVER)
