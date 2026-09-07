.PHONY: all build test lint security tidy verify clean

all: build test lint security

build:
	go build ./...

test:
	go test -race -shuffle=on -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./...

security:
	gosec -quiet ./...
	govulncheck ./...

tidy:
	go mod tidy
	go mod verify

verify: tidy

clean:
	rm -f coverage.out
