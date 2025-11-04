COMMIT_SHA := $(shell git log -1 --pretty=format:"%h")
BUILD_TIMESTAMP=$(shell date "+%Y-%m-%d %H:%M:%S")
BUILD_FLAGS=
BUILD_ENVS=CGO_ENABLED=0;GOARCH=arm64;GOOS=linux
BUILD_CONSTANTS=-ldflags "-X 'antizapret-go/cfg.BuildCommitSha=$(COMMIT_SHA)' -X 'antizapret-go/cfg.BuildTimestamp=$(BUILD_TIMESTAMP)'"

all: antizapret_go

build-dir:
	mkdir -p $(PWD)/build/

antizapret_go: build-dir
	$(BUILD_ENVS) go build $(BUILD_FLAGS) $(BUILD_CONSTANTS) -o $(PWD)/build/$@ $(PWD)/cmd/

lint:
	golangci-lint run --timeout 5m

test:
	go test $(PWD)/...

cover:
	go test -cover $(PWD)/...

bench:
	go test -bench=. $(PWD)/... | grep -v "no test files"

lines:
	find . -name '*.go' | xargs wc -l

.PHONY: all antizapret_go test bench build-dir lint lines cover