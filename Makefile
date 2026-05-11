.PHONY: build test lint cover bench clean

build:
	go build -o bin/pin ./cmd/pin

test:
	go test -race ./...

lint:
	go tool golangci-lint run ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

bench:
	go test -bench=. -benchmem -run='^$$' ./...

clean:
	rm -rf bin/ dist/ coverage.out coverage.html
