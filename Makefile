GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-quay cmd/vault-plugin-secrets-quay/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins -log-level=debug

enable:
	vault secrets enable -path=quay vault-plugin-secrets-quay

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-quay

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
