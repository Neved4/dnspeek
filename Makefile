.POSIX:

.PHONY: all build clean fmt run test tidy vet

progName = dnspeek

all: fmt vet test

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

tidy:
	go mod tidy

build:
	go build -trimpath -ldflags "-s -w" -o $(progName) ./cmd/$(progName)

run:
	go run ./cmd/$(progName)

clean:
	rm -f $(progName)
