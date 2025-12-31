.PHONY: help build run test fmt lint check docker-build docker-run clean

help:
	@echo "Unifi Network MCP Server - Make Commands"
	@echo "========================================"
	@echo "  make build          - Build the network MCP binary"
	@echo "  make run            - Run the network MCP server"
	@echo "  make test           - Run tests"
	@echo "  make fmt            - Format code"
	@echo "  make lint           - Run linter"
	@echo "  make check          - Run all checks (fmt, lint, test)"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-run     - Run Docker container"
	@echo "  make clean          - Clean build artifacts"

build:
	go build -o bin/unifi-network-mcp ./cmd

run: build
	./bin/unifi-network-mcp

test:
	go test -v -cover ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run ./...

check: fmt lint test

docker-build:
	docker build -t unifi-network-mcp:latest .

docker-run: docker-build
	docker run --rm \
		-e UNIFI_NETWORK_URL="$${UNIFI_NETWORK_URL}" \
		-e UNIFI_NETWORK_USERNAME="$${UNIFI_NETWORK_USERNAME}" \
		-e UNIFI_NETWORK_PASSWORD="$${UNIFI_NETWORK_PASSWORD}" \
		unifi-network-mcp:latest

clean:
	rm -rf bin/
	go clean
