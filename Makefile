build:
	go build -v
.PHONY: build

test:
	go test -v -cover
.PHONY: test

clean:
	go clean
.PHONY: clean

generate:
	go generate
.PHONY: generate

all: clean build test
.PHONY: all
