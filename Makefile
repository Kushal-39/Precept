.PHONY: all build test policy-test policy-fmt lint security tidy verify clean

all: build test policy-test lint security

build:
	go build ./...

test:
	go test -race -shuffle=on -coverprofile=coverage.out ./...

policy-test:
	opa test policies/

policy-fmt:
	opa fmt --write policies/

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
