# Common tasks. `make help` lists them. Requires Bun (https://bun.sh) and uv (https://docs.astral.sh/uv/).

HAYBARN_VERSION ?= 2.0.0rc11
WORKER          := $(CURDIR)/bin/vgi-azure-defender-worker
TOOLS           := $(CURDIR)/.tools
HAYBARN_UNITTEST := $(TOOLS)/bin/haybarn-unittest
TRANSPORT       ?= stdio

.DEFAULT_GOAL := help
.PHONY: help build tools typecheck test-unit test-sql test-sql-all test check

help: ## List the targets
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  %-14s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

build: ## Install the worker's dependencies into node_modules
	bun install --frozen-lockfile

tools: ## Install the pinned SQL test runner into .tools
	@test -x $(HAYBARN_UNITTEST) || { uv venv -q $(TOOLS) && uv pip install -q -p $(TOOLS) haybarn-unittest==$(HAYBARN_VERSION); }

typecheck: build ## tsc --noEmit over this repo's own sources
	bun run typecheck

test-unit: build ## Unit tests (bun test)
	bun test

test-sql: build tools ## SQL tests through DuckDB: make test-sql TRANSPORT=stdio|launch|http
	WORKER=$(WORKER) HAYBARN_UNITTEST=$(HAYBARN_UNITTEST) TRANSPORT=$(TRANSPORT) ci/run-integration.sh

test-sql-all: ## SQL tests over every transport
	$(MAKE) test-sql TRANSPORT=stdio
	$(MAKE) test-sql TRANSPORT=launch
	$(MAKE) test-sql TRANSPORT=http

test: test-unit test-sql ## Unit + SQL tests

check: typecheck test-unit test-sql-all ## Everything CI runs except vgi-lint
