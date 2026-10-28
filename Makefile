BIN     := ipt-lens
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race lint demo clean

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/server

test:
	go vet ./...
	go test ./...

race:
	go test -race ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	staticcheck ./...

demo:
	go run ./cmd/server --demo --listen 127.0.0.1:8090

clean:
	rm -f $(BIN)
	rm -rf dist
