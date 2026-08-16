.PHONY: build test lint cover bench fuzz clean

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

# fuzz runs each parser's fuzz target sequentially for FUZZTIME (default
# 30s). The seed corpus runs as a regular `go test` step every CI build;
# this target is for the longer drift-hunting pass. Override duration
# with `make fuzz FUZZTIME=2m`.
FUZZTIME ?= 30s
fuzz:
	go test -fuzz=FuzzParse -fuzztime=$(FUZZTIME) ./source/attestation/
	go test -fuzz=FuzzRead -fuzztime=$(FUZZTIME) ./manifest/
	go test -fuzz=FuzzAddEntry -fuzztime=$(FUZZTIME) ./manifest/
	go test -fuzz=FuzzRemoveEntry -fuzztime=$(FUZZTIME) ./manifest/
	go test -fuzz=FuzzRead -fuzztime=$(FUZZTIME) ./lock/
	go test -fuzz=FuzzFormat -fuzztime=$(FUZZTIME) ./sniff/
	go test -fuzz=FuzzIsSticky -fuzztime=$(FUZZTIME) ./source/npm/
	go test -fuzz=FuzzFindSignature -fuzztime=$(FUZZTIME) ./source/npm/
	go test -fuzz=FuzzSafeOut -fuzztime=$(FUZZTIME) .

clean:
	rm -rf bin/ dist/ coverage.out coverage.html
