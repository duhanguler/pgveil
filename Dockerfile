# syntax=docker/dockerfile:1

# Stage 1: Build embedded React + TypeScript Control Plane UI
FROM node:20-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci || npm install
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binaries (pgveil proxy with embedded UI + pgveil-audit-worker)
FROM golang:1.27-bookworm AS go-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /src/internal/webui/dist ./internal/webui/dist

ARG VERSION=0.1.0
ARG COMMIT=docker
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/pgveil ./cmd/pgveil
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pgveil-audit-worker ./cmd/audit-worker

# Stage 3: Minimal runtime image for pgveil proxy
FROM debian:bookworm-slim AS pgveil
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 pgveil
WORKDIR /app
COPY --from=go-builder /out/pgveil /usr/local/bin/pgveil
COPY configs/pgveil.yaml /app/configs/pgveil.yaml
USER pgveil
EXPOSE 6432 8088
ENTRYPOINT ["pgveil"]
CMD ["serve", "--config", "/app/configs/pgveil.yaml"]

# Stage 4: Minimal runtime image for Kafka audit-worker
FROM debian:bookworm-slim AS audit-worker
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 pgveil
WORKDIR /app
COPY --from=go-builder /out/pgveil-audit-worker /usr/local/bin/pgveil-audit-worker
USER pgveil
EXPOSE 8089
ENTRYPOINT ["pgveil-audit-worker"]
