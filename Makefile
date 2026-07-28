IMAGE ?= ghcr.io/arustydev/external-dns-cloudflare-zerotrust-provider:dev

.PHONY: build test vet tidy docker run help

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'

build: ## Compile all packages
	go build ./...

test: ## Run tests (race + fresh)
	go test -race -count=1 ./...

vet: ## go vet
	go vet ./...

tidy: ## go mod tidy
	go mod tidy

docker: ## Build the container image
	docker build -t $(IMAGE) .

run: ## Run locally (expects CF_* env vars)
	go run ./cmd/webhook
