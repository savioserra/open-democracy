# Convenience targets for the open-democracy project.
#
#   make help        list available targets
#   make test        run unit tests
#   make css         build Tailwind CSS
#   make css-watch   watch Tailwind CSS in dev mode
#   make build       build the gateway binary (runs css first)
#   make run         run the gateway locally on :8080 with ./data persistence
#   make image       build the docker image
#   make up          build odctl and start the demo dashboard via odctl
#   make down        build odctl and stop the demo dashboard via odctl
#   make status      show demo + node status via odctl
#   make node-setup  write federation/democracy.toml via odctl (requires ORG_NAME=...)
#   make node-bootstrap  bootstrap federation crypto via odctl
#   make node-start  start the federation node via odctl
#   make node-stop   stop the federation node via odctl
#   make network-start  generate and start an isolated founding network
#   make network-stop   stop an isolated founding network (requires INSTANCE=...)
#   make tui         launch the odctl TUI
#   make logs        follow gateway container logs
#   make clean       remove ./bin, ./data, and node_modules

GO ?= go
BIN_DIR := bin
DATA_DIR := data
GATEWAY := $(BIN_DIR)/gateway
ODCTL := $(BIN_DIR)/odctl
CSS_INPUT := internal/gateway/web/static/input.css
CSS_OUTPUT := internal/gateway/web/static/style.css
TEMPLATES := $(shell find internal/gateway/web/templates -type f -name '*.html' 2>/dev/null)

.PHONY: help test build run image up down status node-setup node-bootstrap node-start node-stop network-start network-stop tui logs clean tidy fmt vet css css-watch odctl

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' || true
	@echo ""
	@echo "Targets: help test css css-watch build odctl tui run image up down status node-setup node-bootstrap node-start node-stop network-start network-stop logs clean tidy fmt vet"

tidy: ## Run go mod tidy
	$(GO) mod tidy

fmt: ## Format Go code
	$(GO) fmt ./...

vet: ## Vet Go code
	$(GO) vet ./...

test: ## Run unit tests
	$(GO) test ./...

css: $(CSS_OUTPUT) ## Build Tailwind CSS (production, minified)

$(CSS_OUTPUT): $(CSS_INPUT) tailwind.config.js $(TEMPLATES)
	npx tailwindcss -i $(CSS_INPUT) -o $(CSS_OUTPUT) --minify

css-watch: ## Watch Tailwind CSS (dev mode, rebuild on template changes)
	npx tailwindcss -i $(CSS_INPUT) -o $(CSS_OUTPUT) --watch

build: css $(GATEWAY) ## Build the gateway binary

$(GATEWAY): $(shell find cmd/gateway internal/gateway chaincode -type f -name '*.go' 2>/dev/null) $(CSS_OUTPUT) go.mod go.sum
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags="-s -w" -o $(GATEWAY) ./cmd/gateway

odctl: $(ODCTL) ## Build the odctl hybrid CLI

tui: $(ODCTL) ## Launch the odctl TUI
	$(ODCTL) tui

$(ODCTL): $(shell find cmd/odctl internal/tui -type f -name '*.go' 2>/dev/null) go.mod go.sum
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(ODCTL) ./cmd/odctl

run: build ## Run the gateway locally with ./data persistence
	@mkdir -p $(DATA_DIR)
	GATEWAY_DATA=$(DATA_DIR) GATEWAY_ADDR=:8080 GATEWAY_USER=ada $(GATEWAY)

image: ## Build the docker image
	docker build -t open-democracy-gateway:latest .

up: $(ODCTL) ## Start the demo dashboard stack via odctl
	$(ODCTL) demo start

down: $(ODCTL) ## Stop the demo dashboard stack via odctl
	$(ODCTL) demo stop

status: $(ODCTL) ## Show demo and node status via odctl
	$(ODCTL) status

node-setup: $(ODCTL) ## Configure federation/democracy.toml via odctl (requires ORG_NAME)
	@test -n "$(ORG_NAME)" || (echo "ORG_NAME is required, e.g. make node-setup ORG_NAME=city-porto-alegre DISPLAY_NAME='City of Porto Alegre' SCOPE_PREFIX=GOV:CITY_PORTO_ALEGRE" && exit 1)
	$(ODCTL) node setup --org-name "$(ORG_NAME)" $(if $(DISPLAY_NAME),--display-name "$(DISPLAY_NAME)") $(if $(SCOPE_PREFIX),--scope-prefix "$(SCOPE_PREFIX)") $(if $(GATEWAY_PORT),--gateway-port "$(GATEWAY_PORT)")

node-bootstrap: $(ODCTL) ## Bootstrap federation node crypto via odctl
	$(ODCTL) node bootstrap

node-start: $(ODCTL) ## Start the federation node stack via odctl
	$(ODCTL) node start

node-stop: $(ODCTL) ## Stop the federation node stack via odctl
	$(ODCTL) node stop

network-start: $(ODCTL) ## Start an isolated founding network via odctl
	$(ODCTL) network start $(if $(INSTANCE),--instance "$(INSTANCE)")

network-stop: $(ODCTL) ## Stop an isolated founding network via odctl (requires INSTANCE)
	@test -n "$(INSTANCE)" || (echo "INSTANCE is required, e.g. make network-stop INSTANCE=founding-20260413-010000-000000000" && exit 1)
	$(ODCTL) network stop --instance "$(INSTANCE)"

logs: ## Follow gateway container logs
	docker compose logs -f gateway

clean: ## Remove build artefacts and local data
	rm -rf $(BIN_DIR) $(DATA_DIR)
