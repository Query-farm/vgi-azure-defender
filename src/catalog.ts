// The `azure` catalog descriptor + the azure_graph secret type for vgi-azure-defender.
// The secret shape is the app-only client-credentials freeze that directory owns
// (graph-core-SPEC §A); defender re-declares the identical shape here so every
// catalog advertises the same `azure_graph` type independently.
//
// This file also carries the catalog- and schema-level vgi.* documentation/discovery
// tags that vgi-lint grades. Tag shapes follow vgi-lint's TAGS.md: JSON-valued tags
// (keywords/categories/executable_examples/agent_test_tasks/example_queries) are JSON
// strings; every example SQL is catalog-qualified (azure.main.<fn>) so it binds when
// the catalog is attached. The defender functions require an `azure_graph` secret to
// RUN, so the executable examples are credential-free `LIMIT 0` bind probes (onBind
// runs without a secret; process(), where the secret/network lives, is never pumped).

import { Schema, Field, Utf8 } from "@query-farm/apache-arrow";
import type { CatalogDescriptor, SecretTypeDescriptor, VgiFunction } from "@query-farm/vgi";

const REPO = "https://github.com/Query-farm/vgi-azure-defender";
const ISSUES = `${REPO}/issues`;

export const AZURE_GRAPH_SECRET: SecretTypeDescriptor = {
  name: "azure_graph",
  description: "Microsoft Entra app-only (client-credentials) credentials for Microsoft Graph",
  schema: new Schema([
    new Field("tenant_id", new Utf8(), true),
    new Field("client_id", new Utf8(), true),
    new Field("client_secret", new Utf8(), true, new Map([["redact", "true"]])),
  ]),
};

/** Catalog-level tags: docs, discovery, provenance, and the agent-test suite. */
const CATALOG_TAGS: Record<string, string> = {
  "vgi.title": "Microsoft Defender Security",
  "vgi.doc_llm":
    "Microsoft 365 Defender / Microsoft Sentinel security incidents and alerts as SQL watermark " +
    "table functions over the Microsoft Graph security API. Reach for it to sync the tenant's " +
    "security incidents (with their correlated alerts) and its alerts_v2 feed as an incremental, " +
    "at-least-once change stream: each scan returns the incidents/alerts whose lastUpdateDateTime " +
    "advanced since the last cursor, plus a single marker row carrying the next watermark to " +
    "persist. A first call with no `since` performs a bounded cold start (now − lookback, default " +
    "30d); passing a previously saved `_watermark_next` as `since` returns only what changed. The " +
    "boundary is a safety-lagged `ge` window, so late-correlated rows are re-read and applied " +
    "idempotently by id. `status` is a lifecycle field, never a tombstone. Requires an app-only " +
    "(client-credentials) 'azure_graph' secret (tenant_id, client_id, client_secret) with Graph " +
    "security read permission (SecurityIncident.Read.All, SecurityAlert.Read.All).",
  "vgi.doc_md":
    "## Microsoft Defender Security\n\n" +
    "Incremental (watermark) access to Microsoft 365 Defender / Microsoft Sentinel security data " +
    "via the Microsoft Graph security API, exposed as two DuckDB table functions.\n\n" +
    "- **`security_incidents`** — Defender/Sentinel incidents with their correlated alerts " +
    "(`$expand=alerts`) as an incremental feed.\n" +
    "- **`security_alerts`** — the authoritative Defender/Sentinel alerts (`alerts_v2`) feed as an " +
    "incremental feed.\n\n" +
    "Each function returns changed rows plus a single marker row (`_row_kind = 'marker'`) whose " +
    "`_watermark_next` column holds the ISO-8601 cursor to persist and replay as the next scan's " +
    "`since`. Call with no arguments for a bounded cold start; pass `since := '<_watermark_next>'` " +
    "for an incremental sync. The incident watermark does NOT guarantee alert-level freshness — use " +
    "`security_alerts` for authoritative alert completeness. An app-only `azure_graph` secret " +
    "(Microsoft Entra client credentials) is required.",
  "vgi.keywords": JSON.stringify([
    "azure",
    "microsoft defender",
    "microsoft 365 defender",
    "sentinel",
    "microsoft graph",
    "security",
    "incidents",
    "alerts",
    "alerts_v2",
    "watermark",
    "change feed",
    "siem",
    "soc",
    "mitre",
    "threat detection",
  ]),
  "vgi.author": "Query Farm LLC",
  "vgi.copyright": "Copyright 2026 Query Farm LLC",
  "vgi.license": "MIT",
  "vgi.support_contact": ISSUES,
  "vgi.support_policy_url": ISSUES,
  // Guaranteed-runnable, catalog-qualified examples (VGI509/VGI906). A LIVE sync needs
  // an attached azure_graph secret and a network call to Microsoft Graph, so these are
  // credential-free `LIMIT 0` schema/bind probes: they verify each function binds and
  // expose its exact result columns without fetching (and without credentials). Drop the
  // `LIMIT 0` and attach an azure_graph secret to pull real rows — the fuller, data-
  // returning queries live in each function's `examples` and the schema `example_queries`.
  "vgi.executable_examples": JSON.stringify([
    {
      name: "incidents_bind_probe",
      description:
        "Bind security_incidents and expose its result columns (credential-free; drop LIMIT 0 and attach an azure_graph secret to sync real incidents)",
      sql: "SELECT id, incident_id, display_name, status, severity, _row_kind, _watermark_next FROM azure.main.security_incidents() LIMIT 0",
    },
    {
      name: "alerts_bind_probe",
      description:
        "Bind security_alerts and expose its result columns (credential-free; attach an azure_graph secret to sync real alerts)",
      sql: "SELECT id, incident_id, title, status, severity, category, _row_kind, _watermark_next FROM azure.main.security_alerts() LIMIT 0",
    },
    {
      name: "list_feeds",
      description:
        "List the catalog's security feeds from the credential-free manifest view (runs with no secret)",
      sql: "SELECT feed, source_endpoint, requires_secret FROM azure.main.feeds ORDER BY feed",
    },
  ]),
  // The agent-suitability suite (VGI520/VGI920), catalog only. All fields except
  // `prompt` are GRADER-ONLY. A live incident/alert scan needs an azure_graph secret and
  // returns tenant-specific, non-deterministic data, so those tasks omit an exact-compare
  // reference_sql and instead assert a stable structural invariant via check_sql — every
  // scan closes with exactly one marker row — which also records object coverage. The
  // credential-free `feeds` manifest view is graded by an exact check_sql. success_criteria
  // is the LLM-judge fallback describing what a correct analyst answer looks like.
  "vgi.agent_test_tasks": JSON.stringify([
    {
      name: "high_severity_incidents",
      prompt: "List the open high-severity security incidents with their display name and severity.",
      check_sql:
        "SELECT count(*) = 1 FROM azure.main.security_incidents() WHERE _row_kind = 'marker'",
      success_criteria:
        "The answer queries security_incidents(), filters to incident data rows (_row_kind = 'incident'), keeps severity = 'high' and an open status, and returns display_name and severity.",
    },
    {
      name: "save_watermark_cursor",
      prompt: "After syncing incidents, how do I get the cursor to use for the next incremental sync?",
      check_sql:
        "SELECT _watermark_next IS NOT NULL FROM azure.main.security_incidents() WHERE _row_kind = 'marker'",
      success_criteria:
        "The answer selects _watermark_next from the marker row (_row_kind = 'marker') of security_incidents() and explains it should be replayed via the since argument on the next scan.",
    },
    {
      name: "authoritative_alerts",
      prompt: "What is the right way to get a complete, up-to-date list of security alerts?",
      check_sql:
        "SELECT count(*) = 1 FROM azure.main.security_alerts() WHERE _row_kind = 'marker'",
      success_criteria:
        "The answer uses security_alerts() (not the expanded alerts from security_incidents) and explains it is the authoritative alert feed, filtering to alert data rows (_row_kind = 'alert').",
    },
    {
      name: "browse_available_feeds",
      prompt: "What security data feeds does this catalog provide, and which endpoint backs each?",
      check_sql: "SELECT count(*) = 2 FROM azure.main.feeds",
      success_criteria:
        "The answer names both feeds — security_incidents (/security/incidents) and security_alerts (/security/alerts_v2) — e.g. by browsing the feeds view; both are watermark feeds requiring an azure_graph secret.",
    },
  ]),
};

/** The credential-free discovery view: a static manifest of the two watermark feeds an
 *  agent can `SELECT *` from with no secret, so the catalog has a browsable entry point
 *  (VGI146) before any argument is guessed. Self-contained VALUES — no worker RPC. */
const FEEDS_VIEW_TAGS: Record<string, string> = {
  "vgi.category": "discovery",
  domain: "security",
  "vgi.title": "Security Feeds Manifest",
  "vgi.keywords": JSON.stringify([
    "feeds",
    "manifest",
    "catalog",
    "discovery",
    "security",
    "incidents",
    "alerts",
  ]),
  "vgi.doc_llm":
    "A static, credential-free manifest of the security watermark feeds this catalog exposes. " +
    "One row per feed (security_incidents, security_alerts) with its Microsoft Graph source " +
    "endpoint, the _row_kind values it emits, whether it needs an azure_graph secret, and a " +
    "one-line description. Browse it to learn what to call before supplying credentials.",
  "vgi.doc_md":
    "## feeds\n\n" +
    "A credential-free manifest of the two security watermark feeds — a browsable entry point " +
    "for discovery. Each row describes one feed: its `source_endpoint` on the Microsoft Graph " +
    "security API, the `row_kinds` it emits, whether it `requires_secret`, and a short " +
    "`description`. The feeds themselves (`security_incidents`, `security_alerts`) are table " +
    "functions that require an app-only `azure_graph` secret to scan.",
  "vgi.example_queries": JSON.stringify([
    {
      description: "List the available security feeds and their Graph source endpoint",
      sql: "SELECT feed, source_endpoint, requires_secret FROM azure.main.feeds ORDER BY feed",
    },
  ]),
};

const FEEDS_VIEW_COLUMN_COMMENTS: Record<string, string> = {
  feed: "The table-function name to call (security_incidents or security_alerts).",
  source_endpoint: "The Microsoft Graph security API path the feed reads.",
  row_kinds: "The `_row_kind` values the feed emits in its row stream.",
  requires_secret: "Whether scanning the feed needs an app-only azure_graph secret (always true).",
  description: "A one-line summary of what the feed returns.",
};

// A single-statement VALUES scan — self-contained, no worker call, so it binds and scans
// without an azure_graph secret. Column names/order are pinned by the trailing AS list.
const FEEDS_VIEW_DEFINITION =
  "SELECT feed, source_endpoint, row_kinds, requires_secret, description FROM (VALUES " +
  "('security_incidents', '/security/incidents?$expand=alerts', 'incident, alert, marker', true, " +
  "'Microsoft 365 Defender / Sentinel incidents with their correlated alerts as an incremental, safety-lagged lastUpdateDateTime watermark feed.'), " +
  "('security_alerts', '/security/alerts_v2', 'alert, marker', true, " +
  "'The authoritative Microsoft 365 Defender / Sentinel alerts_v2 feed as an incremental, safety-lagged lastUpdateDateTime watermark feed.')" +
  ") AS t(feed, source_endpoint, row_kinds, requires_secret, description)";

/** Schema-level tags: docs, discovery, the category registry, and shown examples. */
const SCHEMA_TAGS: Record<string, string> = {
  "vgi.title": "Defender Security",
  "vgi.doc_llm":
    "The Microsoft 365 Defender / Sentinel security functions. Each is an incremental watermark " +
    "feed over the Microsoft Graph security API — incidents (with correlated alerts) or alerts_v2 " +
    "— cursored by a safety-lagged lastUpdateDateTime `ge` boundary. A scan returns rows updated " +
    "since the supplied `since` cursor, followed by one marker row whose _watermark_next column is " +
    "the cursor to persist for the next scan. Omit `since` for a bounded cold start (now − " +
    "lookback). Capture is at-least-once (the lag window re-reads late rows); apply idempotently by " +
    "id. `status` is a lifecycle field, never a tombstone.",
  "vgi.doc_md":
    "## Defender security watermark functions\n\n" +
    "| Function | Source | Returns |\n" +
    "| --- | --- | --- |\n" +
    "| `security_incidents` | `/security/incidents` (`$expand=alerts`) | changed incidents + their alerts + watermark |\n" +
    "| `security_alerts` | `/security/alerts_v2` | changed alerts + watermark |\n\n" +
    "Both share the same shape: read data rows with `WHERE _row_kind <> 'marker'` (equivalently " +
    "`_watermark_next IS NULL`), and take the next cursor from the single marker row's " +
    "`_watermark_next`. `security_incidents` interleaves `_row_kind` values `incident` and `alert`; " +
    "`security_alerts` emits only `alert`. Use `security_alerts` for authoritative alert " +
    "completeness. Each requires an app-only `azure_graph` secret.",
  "vgi.keywords": JSON.stringify([
    "microsoft defender",
    "sentinel",
    "security",
    "incidents",
    "alerts",
    "alerts_v2",
    "watermark",
    "change feed",
    "mitre",
    "siem",
    "soc",
  ]),
  domain: "security",
  // Ordered navigation registry; each `name` is referenced by a function's vgi.category.
  "vgi.categories": JSON.stringify([
    {
      name: "security-watermark",
      title: "Defender Security Feeds",
      description:
        "Incremental watermark feeds for Microsoft 365 Defender / Sentinel security incidents and alerts via the Microsoft Graph security API.",
    },
    {
      name: "discovery",
      title: "Discovery",
      description:
        "Credential-free browsable entry points that describe the catalog's feeds before any secret or argument is supplied.",
    },
  ]),
  "vgi.example_queries": JSON.stringify([
    {
      description: "Cold-start sync of open high-severity incidents",
      sql: "SELECT id, display_name, severity, status FROM azure.main.security_incidents() WHERE _row_kind = 'incident' AND severity = 'high' AND status = 'active'",
    },
    {
      description: "Incremental incident sync from a saved watermark",
      sql: "SELECT id, display_name, status FROM azure.main.security_incidents(since := '<_watermark_next>') WHERE _row_kind = 'incident'",
    },
    {
      description: "Read the watermark cursor to persist for the next scan",
      sql: "SELECT _watermark_next FROM azure.main.security_incidents() WHERE _row_kind = 'marker'",
    },
    {
      description: "Authoritative alert feed, high severity only",
      sql: "SELECT id, title, severity, category FROM azure.main.security_alerts() WHERE _row_kind = 'alert' AND severity = 'high'",
    },
  ]),
};

export function makeCatalog(functions: VgiFunction[]): CatalogDescriptor {
  return {
    name: "azure",
    defaultSchema: "main",
    comment:
      "Microsoft 365 Defender / Sentinel incidents & alerts via Microsoft Graph security API — " +
      "lastUpdateDateTime watermark cursor (safety-lag, ge boundary, dedup-by-id). vgi-azure-defender",
    sourceUrl: REPO,
    tags: CATALOG_TAGS,
    secretTypes: [AZURE_GRAPH_SECRET],
    schemas: [
      {
        name: "main",
        comment:
          "Microsoft 365 Defender / Sentinel security incidents & alerts as incremental Graph security watermark feeds.",
        tags: SCHEMA_TAGS,
        functions,
        views: [
          {
            name: "feeds",
            definition: FEEDS_VIEW_DEFINITION,
            comment:
              "Credential-free manifest of the security watermark feeds (a browsable discovery entry point).",
            columnComments: FEEDS_VIEW_COLUMN_COMMENTS,
            tags: FEEDS_VIEW_TAGS,
          },
        ],
      },
    ],
  };
}
