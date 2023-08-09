BUILD_DIR := build
BINARY := $(BUILD_DIR)/pack

PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64
VERSION=$(shell git describe --tags --always --dirty)

LDFLAGS=-ldflags "-X main.Version=${VERSION}"


.DEFAULT: build

build:
	go build ${LDFLAGS} -o $(BINARY) main.go

all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES),\
	$(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build -v ${LDFLAGS} -o $(BINARY)-$(VERSION)+$(GOOS)-$(GOARCH) main.go)\
	))


clean:
	rm -rf $(BUILD_DIR)

.PHONY: build build_all install
