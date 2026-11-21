.PHONY: ui build test bench lint helm-lint docker-up docker-down clean

VERSION ?= 0.3.2
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

ui:
	cd web && npm ci && npm run build

build: ui
	go build -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o bin/pgveil ./cmd/pgveil
	go build -ldflags="-s -w" -o bin/pgveil-audit-worker ./cmd/audit-worker

build-go:
	go build -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o bin/pgveil ./cmd/pgveil
	go build -ldflags="-s -w" -o bin/pgveil-audit-worker ./cmd/audit-worker

test:
	go test -race -v ./...

bench:
	go test -bench=. -benchmem ./internal/pii/... ./internal/firewall/...

validate:
	go run ./cmd/pgveil validate --config configs/pgveil.yaml

helm-lint:
	helm lint deploy/helm/pgveil
	helm template pgveil deploy/helm/pgveil > /dev/null

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

clean:
	rm -rf bin/ dist/
