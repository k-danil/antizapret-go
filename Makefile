COMMIT_SHA := $(shell git log -1 --pretty=format:"%h")
BUILD_TIMESTAMP=$(shell date "+%Y-%m-%d %H:%M:%S")
BUILD_FLAGS=
BUILD_ENVS=CGO_ENABLED=0 GOOS=linux
BUILD_CONSTANTS=-ldflags "-X 'github.com/antizapret-vpn/go-proxy/cfg.BuildCommitSha=$(COMMIT_SHA)' -X 'github.com/antizapret-vpn/go-proxy/cfg.BuildTimestamp=$(BUILD_TIMESTAMP)'"

all: antizapret_go

build-dir:
	mkdir -p $(PWD)/build/

antizapret_go: build-dir
	$(BUILD_ENVS) go build $(BUILD_FLAGS) $(BUILD_CONSTANTS) -o $(PWD)/build/$@ $(PWD)/cmd/

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "Not gofmt-ed:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...

lint:
	golangci-lint run --timeout 5m

test:
	go test -race ./...

cover:
	go test -cover ./...

bench:
	go test -bench=. ./... | grep -v "no test files"

# Агрегат для CI: единый источник правды для проверок (кроме lint — он ставится
# и запускается через golangci-lint-action, но с тем же дефолтным конфигом).
ci: fmt-check vet test all

lines:
	find . -name '*.go' | xargs wc -l

.PHONY: all antizapret_go build-dir fmt-check vet lint test cover bench ci lines