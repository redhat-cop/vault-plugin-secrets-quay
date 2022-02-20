GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

GO := go
CGO_ENABLED := 0
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

PKG=github.com/redhat-cop/vault-plugin-secrets-quay/cmd
LDFLAGS=-X $(PKG).gitVersion=$(GIT_VERSION) -X $(PKG).gitCommit=$(GIT_HASH) -X $(PKG).gitTreeState=$(GIT_TREESTATE) -X $(PKG).buildDate=$(BUILD_DATE)


.DEFAULT_GOAL := all

all: fmt build start

GOLANGCI_LINT = $(shell pwd)/bin/golangci-lint
golangci-lint:
	rm -f $(GOLANGCI_LINT) || :
	set -e ;\
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell dirname $(GOLANGCI_LINT)) v1.39.0 ;\


build:
	CGO_ENABLED=$(CGO_ENABLED) go build -trimpath -ldflags "$(LDFLAGS)" -o vault/plugins/vault-plugin-secrets-quay cmd/vault-plugin-secrets-quay/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins -log-level=debug

enable:
	vault secrets enable -path=quay vault-plugin-secrets-quay

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-quay

fmt:
	go fmt $$(go list ./...)

lint: golangci-lint ## Runs golangci-lint linter
	$(GOLANGCI_LINT) run  -n

test: ## Runs go tests
	go test ./...


##################
# release section
##################

.PHONY: release
release: ## Runs goreleaser in release mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --rm-dist

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot: ## Runs goreleaser in snapshot mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist


.PHONY: build clean fmt start enable
