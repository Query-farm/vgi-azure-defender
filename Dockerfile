# Copyright 2026 Query Farm LLC - https://query.farm
#
# Single image serving BOTH transports of the vgi-azure-defender worker:
#   docker run ... IMG            -> HTTP server on $PORT (default 8000; /health, VGI RPC)
#   docker run -i ... IMG stdio   -> stdio worker DuckDB spawns on-host
# See docker-entrypoint.sh. The defender functions need an app-only azure_graph
# credential (tenant/client/secret via ATTACH options) to return rows, but the image
# itself just runs: /health and catalog introspection need no credentials. Egress
# connector to Microsoft Graph; no persistent state volume.
# syntax=docker/dockerfile:1
FROM oven/bun:1

ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/Query-farm/vgi-azure-defender

LABEL org.opencontainers.image.title="vgi-azure-defender" \
      org.opencontainers.image.description="Microsoft 365 Defender / Sentinel security incidents & alerts as incremental Microsoft Graph security watermark feeds for DuckDB/SQL (stdio + HTTP)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      farm.query.vgi.transports='["http","stdio"]'

ENV PORT=8000 \
    NODE_ENV=production

WORKDIR /app

# curl backs the HEALTHCHECK and the CI /health smoke; the driver uses fetch (egress).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . .

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=8s \
    CMD curl -fsS "http://localhost:${PORT}/health" || exit 1

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
