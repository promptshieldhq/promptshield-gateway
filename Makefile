SHELL := /bin/bash

ifneq (,$(wildcard .env))
include .env
export
endif

BINARY    := promptshield
BIN_PATH  := /usr/local/bin/$(BINARY)
CONFIG_DIR := /etc/promptshield
SYSTEMD   := /etc/systemd/system
CMD_PKG   := ./cmd/gateway

VERSION   := $(shell git tag --sort=committerdate 2>/dev/null | tail -1)
LDFLAGS   := "-s -w -X github.com/promptshieldhq/promptshield-gateway/cmd.Version=$(VERSION)"

.DEFAULT_GOAL := help


deps: # Download and tidy Go module dependencies
	@go mod download
	@go mod tidy

build: deps # Build the binary to bin/
	@mkdir -p bin
	@echo "→ building $(BINARY) $(VERSION)"
	@go build -ldflags $(LDFLAGS) -o bin/$(BINARY) $(CMD_PKG)
	@echo "✓ bin/$(BINARY) ready"

run: # Run the gateway (without building)
	@go run $(CMD_PKG)

test: # Run all tests with race detector
	@go test -race ./...

cover: # Open an HTML test-coverage report in the browser
	@go test -v -coverprofile=c.out ./...
	@go tool cover -html=c.out
.PHONY: cover

fmt: # Format all Go source files
	@gofmt -w .

tidy: # Tidy go.mod / go.sum
	@go mod tidy

lint: # Run golangci-lint
	@golangci-lint run ./...

clean: # Remove build artifacts and temp files
	@rm -rf bin c.out
	@echo "✓ cleaned"

docker: # Build the Docker image
	@docker build -t promptshield-gateway .

docker-run: # Run the Docker image (mount policy + env)
	@docker run --rm -p 8080:8080 \
		-v $(PWD)/config/policy.yaml:/app/config/policy.yaml:ro \
		--env-file .env \
		promptshield-gateway

_build-linux-amd64:
	@echo "  → linux/amd64"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags $(LDFLAGS) -a -installsuffix cgo \
		-o bin/$(BINARY)-linux-amd64 $(CMD_PKG)

_build-linux-arm64:
	@echo "  → linux/arm64"
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -ldflags $(LDFLAGS) -a -installsuffix cgo \
		-o bin/$(BINARY)-linux-arm64 $(CMD_PKG)

_build-darwin-amd64:
	@echo "  → darwin/amd64"
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
		go build -ldflags $(LDFLAGS) -a -installsuffix cgo \
		-o bin/$(BINARY)-darwin-amd64 $(CMD_PKG)

_build-darwin-arm64:
	@echo "  → darwin/arm64"
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
		go build -ldflags $(LDFLAGS) -a -installsuffix cgo \
		-o bin/$(BINARY)-darwin-arm64 $(CMD_PKG)

_build-windows:
	@echo "  → windows/amd64"
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -ldflags $(LDFLAGS) -a -installsuffix cgo \
		-o bin/$(BINARY)-windows-amd64.exe $(CMD_PKG)

dist: deps # Build distribution binaries for all platforms
	@mkdir -p bin
	@echo "Building $(BINARY) $(VERSION) for all platforms…"
	@$(MAKE) -s _build-linux-amd64
	@$(MAKE) -s _build-linux-arm64
	@$(MAKE) -s _build-darwin-amd64
	@$(MAKE) -s _build-darwin-arm64
	@$(MAKE) -s _build-windows
	@echo "✓ all binaries in bin/"

install: build # Install binary + config + systemd service (run as root)
	@[ "$(shell id -u)" = "0" ] || { echo "error: run as root (sudo make install)"; exit 1; }
	@echo "→ creating system user 'promptshield' (if not exists)"
	@id -u promptshield &>/dev/null || useradd --system --no-create-home --shell /bin/false promptshield
	@echo "→ installing binary to $(BIN_PATH)"
	@install -m 755 bin/$(BINARY) $(BIN_PATH)
	@echo "→ creating config dir $(CONFIG_DIR)"
	@install -d -m 750 -o promptshield -g promptshield $(CONFIG_DIR)
	@echo "→ installing default policy (skipped if already exists)"
	@[ -f $(CONFIG_DIR)/policy.yaml ] || install -m 640 -o promptshield -g promptshield config/policy.yaml $(CONFIG_DIR)/policy.yaml
	@echo "→ installing env template (skipped if already exists)"
	@[ -f $(CONFIG_DIR)/.env ] || install -m 640 -o promptshield -g promptshield .env.example $(CONFIG_DIR)/.env
	@echo "→ installing systemd service"
	@install -m 644 infra/systemd/promptshield.service $(SYSTEMD)/promptshield.service
	@systemctl daemon-reload
	@systemctl enable promptshield
	@echo ""
	@echo "✓ Done. Edit $(CONFIG_DIR)/.env, then: sudo systemctl start promptshield"
	@echo "  Logs: journalctl -u promptshield -f"

install-service: # Re-install only the systemd service file (run as root)
	@[ "$(shell id -u)" = "0" ] || { echo "error: run as root (sudo make install-service)"; exit 1; }
	@install -m 644 infra/systemd/promptshield.service $(SYSTEMD)/promptshield.service
	@systemctl daemon-reload
	@echo "✓ service file updated; restart to apply: sudo systemctl restart promptshield"

uninstall: # Remove binary and systemd service (config preserved) (run as root)
	@[ "$(shell id -u)" = "0" ] || { echo "error: run as root (sudo make uninstall)"; exit 1; }
	-@systemctl disable --now promptshield 2>/dev/null
	-@rm -f $(SYSTEMD)/promptshield.service
	@systemctl daemon-reload
	-@rm -f $(BIN_PATH)
	@echo ""
	@echo "✓ binary and service removed, config preserved at $(CONFIG_DIR)"
	@echo "  Remove manually if no longer needed: sudo rm -rf $(CONFIG_DIR)"

help: # Show this help
	@egrep -h '\s#\s' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: deps build run test fmt tidy lint clean \
        docker docker-run \
        dist _build-linux-amd64 _build-linux-arm64 _build-darwin-amd64 _build-darwin-arm64 _build-windows \
        install install-service uninstall help
