.DEFAULT_GOAL := build
GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*")
SHELL=/bin/bash

clean:
	@rm -f orbital

test:
	@go test -v

format:
	@gofmt -s -w ${GOFILES_NOVENDOR}

coverage:
	go test -coverprofile=coverage.out 
	@go tool cover -html=coverage.out

build:
	@go build .

check:
	@if [ -n "$(shell gofmt -l ${GOFILES_NOVENDOR})" ]; then \
		echo 1>&2 'The following files need to be formatted:'; \
		gofmt -l .; \
		exit 1; \
		fi

vet:
	@go vet ${GOFILES_NOVENDOR}

lint:
	@golint ${GOFILES_NOVENDOR}


