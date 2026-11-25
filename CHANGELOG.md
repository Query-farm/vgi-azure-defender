# Changelog

## 0.5.0 (2026-11-25)

- VGI protocol 3.4: bump @query-farm/vgi to 0.52.3 and @query-farm/vgi-rpc to 0.30.3. **Requires the
  3.4 vgi extension**: DuckDB 2.0 (`INSTALL vgi FROM query_farm`) or Haybarn 2.0.1+; Haybarn 2.0.0
  still serves the 3.3 extension, which cannot attach this worker.
- The Docker image supports Orchard hosted mode (`VGI_ORCHARD_HOSTED=1`): HTTP only, Orchard Pass
  authentication, large values through the Orchard blob vendor; the HEALTHCHECK uses `HEAD /health`.
- CI and `make` run the SQL tests on haybarn-unittest 2.0.1rc3.

## 0.4.3 (2026-11-16)

- SQL tests run over stdio, launch and http (the starter's run-integration.sh).

## 0.4.2 (2026-11-16)

- Bump @query-farm/vgi to 0.50.1.

## 0.4.1 — 2026-11-14

- Docs link to Microsoft Graph: the catalog's `vgi.doc_md` / `vgi.doc_llm` now carry a "Sources and
  references" section linking the Microsoft Learn API and permission docs for the endpoints this
  worker calls (vgi-lint VGI183).
