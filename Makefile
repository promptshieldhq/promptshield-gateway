ifneq (,$(wildcard .env))
include .env
export
endif

BINARY     := promptshield
BIN_PATH   := /usr/local/bin/$(BINARY)
CONFIG_DIR := /etc/promptshield
SYSTEMD    := /etc/systemd/system

## dev

build:
	go build -o bin/$(BINARY) ./cmd/proxy

run:
	go run ./cmd/proxy

test:
	go test -race ./...

tidy:
	go mod tidy

lint:
	golangci-lint run ./...

docker:
	docker build -t promptshield-proxy .

# Run the built image. Mount your policy file and pass env vars:
#   make docker-run ANTHROPIC_API_KEY=sk-ant-...
docker-run:
	docker run --rm -p 8080:8080 \
		-v $(PWD)/config/policy.yaml:/app/config/policy.yaml:ro \
		--env-file .env \
		promptshield-proxy

## install

install: build
	@[ "$(shell id -u)" = "0" ] || { echo "error: run as root (sudo make install)"; exit 1; }
	@echo "→ creating system user 'promptshield' (if not exists)"
	id -u promptshield &>/dev/null || useradd --system --no-create-home --shell /bin/false promptshield
	@echo "→ installing binary to $(BIN_PATH)"
	install -m 755 bin/$(BINARY) $(BIN_PATH)
	@echo "→ creating config dir $(CONFIG_DIR)"
	install -d -m 750 -o promptshield -g promptshield $(CONFIG_DIR)
	@echo "→ installing default policy (skipped if already exists)"
	[ -f $(CONFIG_DIR)/policy.yaml ] || install -m 640 -o promptshield -g promptshield config/policy.yaml $(CONFIG_DIR)/policy.yaml
	@echo "→ installing env template (skipped if already exists)"
	[ -f $(CONFIG_DIR)/.env ] || install -m 640 -o promptshield -g promptshield .env.example $(CONFIG_DIR)/.env
	@echo "→ installing systemd service"
	install -m 644 infra/systemd/promptshield.service $(SYSTEMD)/promptshield.service
	systemctl daemon-reload
	systemctl enable promptshield
	@echo ""
	@echo "Done. Edit $(CONFIG_DIR)/.env, then: sudo systemctl start promptshield"
	@echo "Logs: journalctl -u promptshield -f"

# Re-install only the service file (useful after updating infra/systemd/promptshield.service)
install-service:
	@[ "$(shell id -u)" = "0" ] || { echo "error: run as root (sudo make install-service)"; exit 1; }
	install -m 644 infra/systemd/promptshield.service $(SYSTEMD)/promptshield.service
	systemctl daemon-reload
	@echo "Service file updated. Restart to apply: sudo systemctl restart promptshield"

uninstall:
	@[ "$(shell id -u)" = "0" ] || { echo "error: run as root (sudo make uninstall)"; exit 1; }
	-systemctl disable --now promptshield 2>/dev/null
	-rm -f $(SYSTEMD)/promptshield.service
	systemctl daemon-reload
	-rm -f $(BIN_PATH)
	@echo ""
	@echo "Binary and service removed. Config preserved at $(CONFIG_DIR)"
	@echo "Remove manually if no longer needed: sudo rm -rf $(CONFIG_DIR)"

.PHONY: build run test tidy lint docker docker-run install install-service uninstall
