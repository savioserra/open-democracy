# Convenience targets for the open-democracy project.
#
#   make help        list available targets
#   make test        run unit tests
#   make css         build Tailwind CSS
#   make css-watch   watch Tailwind CSS in dev mode
#   make build       build the gateway binary (runs css first)
#   make run         run the gateway locally on :8080 with ./data persistence
#   make image       build the docker image
#   make up          docker compose up --build (detached)
#   make down        docker compose down
#   make logs        follow gateway container logs
#   make clean       remove ./bin, ./data, and node_modules

GO ?= go
BIN_DIR := bin
DATA_DIR := data
GATEWAY := $(BIN_DIR)/gateway
CSS_INPUT := internal/gateway/web/static/input.css
CSS_OUTPUT := internal/gateway/web/static/style.css
TEMPLATES := $(shell find internal/gateway/web/templates -type f -name '*.html' 2>/dev/null)

.PHONY: help test build run image up down logs clean tidy fmt vet css css-watch

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' || true
	@echo ""
	@echo "Targets: help test css css-watch build run image up down logs clean tidy fmt vet"

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

$(GATEWAY): $(shell find cmd internal chaincode -type f -name '*.go' 2>/dev/null) $(CSS_OUTPUT) go.mod go.sum
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags="-s -w" -o $(GATEWAY) ./cmd/gateway

run: build ## Run the gateway locally with ./data persistence
	@mkdir -p $(DATA_DIR)
	GATEWAY_DATA=$(DATA_DIR) GATEWAY_ADDR=:8080 GATEWAY_USER=ada $(GATEWAY)

image: ## Build the docker image
	docker build -t open-democracy-gateway:latest .

up: ## Bring the compose stack up (detached)
	docker compose up --build -d
	@echo "Dashboard: http://localhost:8080/"

down: ## Stop the compose stack
	docker compose down

logs: ## Follow gateway container logs
	docker compose logs -f gateway

clean: ## Remove build artefacts and local data
	rm -rf $(BIN_DIR) $(DATA_DIR)
