.PHONY: all build clean

BINARY=wallguard
VERSION=0.2

# 默认构建当前平台
all: build

# 构建当前平台
build:
	go build -o $(BINARY) ./cmd/wallguard

# 构建所有平台
release: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o target/$(BINARY)-$(VERSION)-linux_amd64 ./cmd/wallguard

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o target/$(BINARY)-$(VERSION)-linux_arm64 ./cmd/wallguard

darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o target/$(BINARY)-$(VERSION)-darwin_amd64 ./cmd/wallguard

darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o target/$(BINARY)-$(VERSION)-darwin_arm64 ./cmd/wallguard

clean:
	rm -rf target $(BINARY)
