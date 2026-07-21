// The VGI table functions: security_incidents + security_alerts. Both are TABLE
// functions so `name := value` works (scalars are positional-only — vgi-scalar-no-
// named-args). Optional args live in `argDefaults` so callers pass them named.
//
// The cross-scan cursor is `since` IN (a previously persisted `_watermark_next`,
// or "" for a bounded cold start) / `_watermark_next` OUT on the marker row — the
// lagged-watermark archetype (SPEC §2). State objects are fully serializable:
// `startUrl` (opaque string), the resolved `since` string, `now` epoch-ms, and a
// `done` flag — no Date, no RecordBatch, no socket.
//
// The GraphClient is injected via ClientFactory so the worker wires the real
// MSAL-backed graph-audience client and tests inject a fake (no SDK, no network).

import { defineTableFunction, secretsOfType, type OutputCollector } from "@query-farm/vgi";
import { Utf8 } from "@query-farm/apache-arrow";
import {
  collectIncidents,
  collectAlerts,
  buildIncidentsUrl,
  buildAlertsUrl,
  resolveSince,
  DEFAULT_LAG_MS,
} from "./defender.js";
import { INCIDENT_SCHEMA, ALERT_SCHEMA, buildWatermarkBatch } from "./schema.js";
import type { GraphClient } from "@vgi-azure/graph-core";

export type ClientFactory = (secret: Record<string, unknown>) => GraphClient;

// Static result schemas as structured {name,type,description} rows (vgi.result_columns_schema,
// VGI307/VGI910). Types are the DuckDB canonicalization of schema.ts's Arrow fields
// (Utf8→VARCHAR, Int32→INTEGER, Bool→BOOLEAN, List<Utf8>→VARCHAR[]); order matches
// INCIDENT_SCHEMA / ALERT_SCHEMA exactly so VGI910's DESCRIBE cross-check lines up.
interface ResultColumn { name: string; type: string; description: string }

const INCIDENT_RESULT_COLUMNS: ResultColumn[] = [
  { name: "id", type: "VARCHAR", description: "The incident id (`incident` rows) or alert id (`alert` rows). NULL on the marker row." },
  { name: "incident_id", type: "VARCHAR", description: "On an `incident` row, its own id; on an `alert` row, the parent incident id." },
  { name: "display_name", type: "VARCHAR", description: "Incident display name (`incident` rows only; NULL otherwise)." },
  { name: "title", type: "VARCHAR", description: "Alert title (`alert` rows only; NULL otherwise)." },
  { name: "status", type: "VARCHAR", description: "Lifecycle status (e.g. `active`, `resolved`) — a field, never a tombstone." },
  { name: "severity", type: "VARCHAR", description: "Severity (`informational`, `low`, `medium`, `high`)." },
  { name: "classification", type: "VARCHAR", description: "Triage classification (e.g. `truePositive`, `falsePositive`)." },
  { name: "determination", type: "VARCHAR", description: "Triage determination (e.g. `malware`, `phishing`)." },
  { name: "assigned_to", type: "VARCHAR", description: "Analyst the incident is assigned to (`incident` rows only; analyst PII)." },
  { name: "tenant_id", type: "VARCHAR", description: "Owning tenant id (`incident` rows only)." },
  { name: "incident_web_url", type: "VARCHAR", description: "Portal deep-link to the incident (`incident` rows only)." },
  { name: "alert_count", type: "INTEGER", description: "Reported number of alerts on the incident (`incident` rows only)." },
  { name: "_alerts_truncated", type: "BOOLEAN", description: "True when the incident's real alert count exceeds the fetched cap — fall back to security_alerts (`incident` rows only)." },
  { name: "category", type: "VARCHAR", description: "Alert category (`alert` rows only)." },
  { name: "service_source", type: "VARCHAR", description: "Alert-producing service, e.g. `microsoftDefenderForEndpoint` (`alert` rows only)." },
  { name: "detection_source", type: "VARCHAR", description: "Detection source of the alert (`alert` rows only)." },
  { name: "mitre_techniques", type: "VARCHAR[]", description: "MITRE ATT&CK technique ids for the alert (`alert` rows only)." },
  { name: "first_activity_datetime", type: "VARCHAR", description: "ISO-8601 first observed activity (`alert` rows only)." },
  { name: "last_activity_datetime", type: "VARCHAR", description: "ISO-8601 last observed activity (`alert` rows only)." },
  { name: "created_datetime", type: "VARCHAR", description: "ISO-8601 creation time." },
  { name: "last_update_datetime", type: "VARCHAR", description: "ISO-8601 last update — the field the watermark is folded from." },
  { name: "_row_kind", type: "VARCHAR", description: "`incident`, `alert`, or `marker` for the single trailing cursor row." },
  { name: "_watermark_next", type: "VARCHAR", description: "On the marker row, the ISO-8601 watermark to persist and replay as the next `since`; NULL on data rows." },
];

const ALERT_RESULT_COLUMNS: ResultColumn[] = [
  { name: "id", type: "VARCHAR", description: "The alert id. NULL on the marker row." },
  { name: "incident_id", type: "VARCHAR", description: "Parent incident id, if the alert is correlated (may be NULL for a standalone alert)." },
  { name: "title", type: "VARCHAR", description: "Alert title." },
  { name: "status", type: "VARCHAR", description: "Lifecycle status (e.g. `new`, `inProgress`, `resolved`) — a field, never a tombstone." },
  { name: "severity", type: "VARCHAR", description: "Severity (`informational`, `low`, `medium`, `high`)." },
  { name: "classification", type: "VARCHAR", description: "Triage classification (e.g. `truePositive`, `falsePositive`)." },
  { name: "determination", type: "VARCHAR", description: "Triage determination (e.g. `malware`, `phishing`)." },
  { name: "category", type: "VARCHAR", description: "Alert category." },
  { name: "service_source", type: "VARCHAR", description: "Alert-producing service, e.g. `microsoftDefenderForEndpoint`." },
  { name: "detection_source", type: "VARCHAR", description: "Detection source of the alert." },
  { name: "mitre_techniques", type: "VARCHAR[]", description: "MITRE ATT&CK technique ids for the alert." },
  { name: "first_activity_datetime", type: "VARCHAR", description: "ISO-8601 first observed activity." },
  { name: "last_activity_datetime", type: "VARCHAR", description: "ISO-8601 last observed activity." },
  { name: "created_datetime", type: "VARCHAR", description: "ISO-8601 creation time." },
  { name: "last_update_datetime", type: "VARCHAR", description: "ISO-8601 last update — the field the watermark is folded from." },
  { name: "_row_kind", type: "VARCHAR", description: "`alert`, or `marker` for the single trailing cursor row." },
  { name: "_watermark_next", type: "VARCHAR", description: "On the marker row, the ISO-8601 watermark to persist and replay as the next `since`; NULL on data rows." },
];

/** Parse a lookback like `30d`, `12h`, `45m`, or a bare ms count. `0` opts into a
 *  full historical backfill (SPEC §2 step 1). */
export function lookbackMs(spec: string): number {
  const m = /^(\d+)\s*([dhms]?)$/.exec(spec.trim());
  if (!m) return 30 * 24 * 60 * 60 * 1000; // fall back to 30d on garbage
  const n = Number(m[1]);
  switch (m[2]) {
    case "d": return n * 24 * 60 * 60 * 1000;
    case "h": return n * 60 * 60 * 1000;
    case "m": return n * 60 * 1000;
    case "s": return n * 1000;
    default: return n; // bare number → ms
  }
}

interface CommonArgs {
  /** A previously persisted `_watermark_next` (ISO-8601), or "" for a bounded cold start. */
  since: string;
  /** Optional caller `$filter`, AND-combined with the `lastUpdateDateTime ge` boundary. */
  filter: string;
  /** Cold-start bound: empty `since` resolves to `now - lookback`. Default 30d. */
  lookback: string;
}
interface IncidentsArgs extends CommonArgs {
  /** Cap on the nested `$expand=alerts($top=N)` set. Default 50. */
  max_alerts: string;
}

interface State {
  done: boolean;
  startUrl: string;
  since: string; // the resolved ISO watermark this scan filters from (`ge since`)
  nowMs: number; // pinned once at bind so clampWatermark is deterministic within a scan
  maxAlerts: number;
}

function requireSecret(fn: string, secrets: unknown): Record<string, unknown> {
  const secret = secretsOfType(secrets as never, "azure_graph")[0];
  if (!secret) throw new Error(`${fn}: attach an 'azure_graph' secret (TYPE azure_graph)`);
  return secret as Record<string, unknown>;
}

export function makeIncidentsFunction(clientFactory: ClientFactory) {
  return defineTableFunction<IncidentsArgs, State>({
    name: "security_incidents",
    description:
      "Microsoft 365 Defender / Sentinel incidents (with $expand=alerts) via Microsoft Graph, " +
      "cursored by a lastUpdateDateTime watermark (safety-lag, ge boundary, dedup-by-id). " +
      "status is a lifecycle field, NOT a tombstone. Incident watermark does NOT guarantee " +
      "alert freshness — use security_alerts for alert-level completeness.",
    args: { since: new Utf8(), filter: new Utf8(), lookback: new Utf8(), max_alerts: new Utf8() },
    argDefaults: { since: "", filter: "", lookback: "30d", max_alerts: "50" },
    argDocs: {
      since:
        "A previously persisted `_watermark_next` (ISO-8601) from a prior scan's marker row, replayed as the `lastUpdateDateTime ge` boundary to return only incidents changed since. Empty (the default) performs a bounded cold start at `now − lookback`.",
      filter:
        "An optional extra Microsoft Graph OData `$filter`, AND-combined with the `lastUpdateDateTime ge <since>` boundary (e.g. `severity eq 'high'`). Empty (the default) applies no extra filter.",
      lookback:
        "Cold-start window used only when `since` is empty: the scan starts at `now − lookback`. Accepts `30d`, `12h`, `45m`, `30s`, or a bare millisecond count; `0` opts into a full historical backfill. Defaults to `30d`.",
      max_alerts:
        "Cap on the nested `$expand=alerts($top=N)` set fetched per incident. When an incident's real alert count exceeds this cap, its incident row's `_alerts_truncated` is true — fall back to `security_alerts` for the complete alert set. Defaults to `50`.",
    },
    examples: [
      {
        sql: "SELECT id, display_name, severity, status FROM azure.main.security_incidents() WHERE _row_kind = 'incident'",
        description: "Cold-start sync of all incidents (incident rows only)",
      },
      {
        sql: "SELECT id, display_name, status FROM azure.main.security_incidents(since := '<_watermark_next>') WHERE _row_kind = 'incident'",
        description: "Incremental sync replaying a previously saved watermark cursor",
      },
      {
        sql: "SELECT incident_id, title, severity FROM azure.main.security_incidents() WHERE _row_kind = 'alert'",
        description: "The alerts correlated to each incident (convenience join; use security_alerts for completeness)",
      },
      {
        sql: "SELECT _watermark_next FROM azure.main.security_incidents() WHERE _row_kind = 'marker'",
        description: "Read the watermark cursor to persist for the next sync",
      },
      {
        sql: "SELECT id, display_name, severity FROM azure.main.security_incidents(filter := 'severity eq ''high''') WHERE _row_kind = 'incident'",
        description: "Server-side severity pushdown via the OData filter argument (fetches fewer rows than a client-side WHERE)",
      },
    ],
    tags: {
      "vgi.category": "security-watermark",
      "vgi.title": "Defender Incidents Feed",
      "vgi.keywords": JSON.stringify([
        "microsoft defender",
        "microsoft 365 defender",
        "sentinel",
        "incidents",
        "incident",
        "security",
        "watermark",
        "change feed",
        "correlated alerts",
        "soc",
      ]),
      "vgi.doc_llm":
        "Incremental watermark feed of Microsoft 365 Defender / Sentinel security incidents (with " +
        "their correlated alerts via `$expand=alerts`) over the Microsoft Graph security API. Each " +
        "scan returns incidents whose lastUpdateDateTime advanced since the supplied `since` cursor, " +
        "each incident interleaved with its capped expanded alert rows, followed by a marker row " +
        "whose _watermark_next is the cursor to persist. Rows carry `_row_kind` 'incident' or " +
        "'alert'; read them with WHERE _row_kind <> 'marker'. Call with no `since` for a bounded " +
        "cold start (now − lookback). `status` is a lifecycle field, never a tombstone; the incident " +
        "watermark does NOT guarantee alert freshness — use security_alerts for alert completeness.",
      "vgi.doc_md":
        "## security_incidents\n\n" +
        "Microsoft 365 Defender / Sentinel incidents as an incremental watermark feed backed by the " +
        "Microsoft Graph `/security/incidents` endpoint (`$expand=alerts`). The row stream " +
        "interleaves incident rows (`_row_kind = 'incident'`) with their correlated alert rows " +
        "(`_row_kind = 'alert'`, `incident_id` = parent), closed by one marker row " +
        "(`_row_kind = 'marker'`) whose `_watermark_next` is the cursor to persist.\n\n" +
        "Read incident rows with `WHERE _row_kind = 'incident'`, take the next cursor from the " +
        "marker row, and replay it as `since` on the next scan (see the examples). The expanded " +
        "alerts are a convenience join only; use `security_alerts` for authoritative alert " +
        "completeness (`_alerts_truncated` flags a capped incident).",
      "vgi.result_columns_schema": JSON.stringify(INCIDENT_RESULT_COLUMNS),
      // VGI515: the native duckdb_functions().examples carrier drops descriptions,
      // so carry a byte-identical described-JSON copy of `examples` as a tag.
      "vgi.example_queries": JSON.stringify([
        {
          description: "Cold-start sync of all incidents (incident rows only)",
          sql: "SELECT id, display_name, severity, status FROM azure.main.security_incidents() WHERE _row_kind = 'incident'",
        },
        {
          description: "Incremental sync replaying a previously saved watermark cursor",
          sql: "SELECT id, display_name, status FROM azure.main.security_incidents(since := '<_watermark_next>') WHERE _row_kind = 'incident'",
        },
        {
          description: "The alerts correlated to each incident (convenience join; use security_alerts for completeness)",
          sql: "SELECT incident_id, title, severity FROM azure.main.security_incidents() WHERE _row_kind = 'alert'",
        },
        {
          description: "Read the watermark cursor to persist for the next sync",
          sql: "SELECT _watermark_next FROM azure.main.security_incidents() WHERE _row_kind = 'marker'",
        },
        {
          description: "Server-side severity pushdown via the OData filter argument (fetches fewer rows than a client-side WHERE)",
          sql: "SELECT id, display_name, severity FROM azure.main.security_incidents(filter := 'severity eq ''high''') WHERE _row_kind = 'incident'",
        },
      ]),
    },
    onBind: () => ({ outputSchema: INCIDENT_SCHEMA }),
    initialState: (p) => {
      const nowMs = Date.now();
      const maxAlerts = Math.max(1, Number(p.args.max_alerts) || 50);
      const since = resolveSince(p.args.since, lookbackMs(p.args.lookback), nowMs);
      return {
        done: false,
        since,
        nowMs,
        maxAlerts,
        startUrl: buildIncidentsUrl(since, p.args.filter, maxAlerts),
      };
    },
    process: async (p, state: State, out: OutputCollector) => {
      if (state.done) {
        out.finish();
        return;
      }
      const secret = requireSecret("security_incidents", p.secrets);
      const client = clientFactory(secret);
      const { rows, watermarkNext } = await collectIncidents(
        client.fetchJson,
        state.startUrl,
        state.since,
        state.maxAlerts,
        state.nowMs,
        DEFAULT_LAG_MS,
      );
      out.emit(buildWatermarkBatch("incidents", INCIDENT_SCHEMA, rows, watermarkNext));
      state.done = true; // next process() hits the done branch and finishes.
    },
  });
}

export function makeAlertsFunction(clientFactory: ClientFactory) {
  return defineTableFunction<CommonArgs, State>({
    name: "security_alerts",
    description:
      "Microsoft 365 Defender / Sentinel alerts (alerts_v2) via Microsoft Graph, cursored by a " +
      "lastUpdateDateTime watermark (safety-lag, ge boundary, dedup-by-id). REQUIRED source of " +
      "truth for alert-level completeness — an alert can be re-stamped without bumping its parent " +
      "incident past the incident watermark, so security_incidents' expanded alerts are a " +
      "convenience join only, not the authoritative alert feed.",
    args: { since: new Utf8(), filter: new Utf8(), lookback: new Utf8() },
    argDefaults: { since: "", filter: "", lookback: "30d" },
    argDocs: {
      since:
        "A previously persisted `_watermark_next` (ISO-8601) from a prior scan's marker row, replayed as the `lastUpdateDateTime ge` boundary to return only alerts changed since. Empty (the default) performs a bounded cold start at `now − lookback`.",
      filter:
        "An optional extra Microsoft Graph OData `$filter`, AND-combined with the `lastUpdateDateTime ge <since>` boundary (e.g. `severity eq 'high'`). Empty (the default) applies no extra filter.",
      lookback:
        "Cold-start window used only when `since` is empty: the scan starts at `now − lookback`. Accepts `30d`, `12h`, `45m`, `30s`, or a bare millisecond count; `0` opts into a full historical backfill. Defaults to `30d`.",
    },
    examples: [
      {
        sql: "SELECT id, title, severity, category FROM azure.main.security_alerts() WHERE _row_kind = 'alert'",
        description: "Cold-start sync of all alerts (alert rows only)",
      },
      {
        sql: "SELECT id, title, status FROM azure.main.security_alerts(since := '<_watermark_next>') WHERE _row_kind = 'alert'",
        description: "Incremental sync replaying a previously saved watermark cursor",
      },
      {
        sql: "SELECT id, title, severity FROM azure.main.security_alerts() WHERE _row_kind = 'alert' AND severity = 'high'",
        description: "High-severity alerts only",
      },
      {
        sql: "SELECT _watermark_next FROM azure.main.security_alerts() WHERE _row_kind = 'marker'",
        description: "Read the watermark cursor to persist for the next sync",
      },
      {
        sql: "SELECT id, title, severity FROM azure.main.security_alerts(filter := 'severity eq ''high''') WHERE _row_kind = 'alert'",
        description: "Server-side severity pushdown via the OData filter argument (fetches fewer rows than a client-side WHERE)",
      },
    ],
    tags: {
      "vgi.category": "security-watermark",
      "vgi.title": "Defender Alerts Feed",
      "vgi.keywords": JSON.stringify([
        "microsoft defender",
        "microsoft 365 defender",
        "sentinel",
        "alerts",
        "alerts_v2",
        "alert",
        "security",
        "watermark",
        "change feed",
        "mitre",
        "soc",
      ]),
      "vgi.doc_llm":
        "Incremental watermark feed of Microsoft 365 Defender / Sentinel alerts (`alerts_v2`) over the " +
        "Microsoft Graph security API — the AUTHORITATIVE alert source. Each scan returns alerts whose " +
        "lastUpdateDateTime advanced since the supplied `since` cursor, followed by a marker row whose " +
        "_watermark_next is the cursor to persist. Rows carry `_row_kind` 'alert'; read them with " +
        "WHERE _row_kind <> 'marker'. Call with no `since` for a bounded cold start (now − lookback). " +
        "An alert can be re-stamped without bumping its parent incident past the incident watermark, " +
        "so security_incidents' expanded alerts are a convenience join only — this feed is the source " +
        "of truth for alert-level completeness. `status` is a lifecycle field, never a tombstone.",
      "vgi.doc_md":
        "## security_alerts\n\n" +
        "Microsoft 365 Defender / Sentinel alerts as an incremental watermark feed backed by the " +
        "Microsoft Graph `/security/alerts_v2` endpoint. Read alert rows (`_row_kind = 'alert'`) and " +
        "take the next cursor from the single marker row's `_watermark_next` (see the examples).\n\n" +
        "This is the authoritative alert feed; the alerts expanded by `security_incidents` are a " +
        "convenience join only.",
      "vgi.result_columns_schema": JSON.stringify(ALERT_RESULT_COLUMNS),
      // VGI515: the native duckdb_functions().examples carrier drops descriptions,
      // so carry a byte-identical described-JSON copy of `examples` as a tag.
      "vgi.example_queries": JSON.stringify([
        {
          description: "Cold-start sync of all alerts (alert rows only)",
          sql: "SELECT id, title, severity, category FROM azure.main.security_alerts() WHERE _row_kind = 'alert'",
        },
        {
          description: "Incremental sync replaying a previously saved watermark cursor",
          sql: "SELECT id, title, status FROM azure.main.security_alerts(since := '<_watermark_next>') WHERE _row_kind = 'alert'",
        },
        {
          description: "High-severity alerts only",
          sql: "SELECT id, title, severity FROM azure.main.security_alerts() WHERE _row_kind = 'alert' AND severity = 'high'",
        },
        {
          description: "Read the watermark cursor to persist for the next sync",
          sql: "SELECT _watermark_next FROM azure.main.security_alerts() WHERE _row_kind = 'marker'",
        },
        {
          description: "Server-side severity pushdown via the OData filter argument (fetches fewer rows than a client-side WHERE)",
          sql: "SELECT id, title, severity FROM azure.main.security_alerts(filter := 'severity eq ''high''') WHERE _row_kind = 'alert'",
        },
      ]),
    },
    onBind: () => ({ outputSchema: ALERT_SCHEMA }),
    initialState: (p) => {
      const nowMs = Date.now();
      const since = resolveSince(p.args.since, lookbackMs(p.args.lookback), nowMs);
      return {
        done: false,
        since,
        nowMs,
        maxAlerts: 0,
        startUrl: buildAlertsUrl(since, p.args.filter),
      };
    },
    process: async (p, state: State, out: OutputCollector) => {
      if (state.done) {
        out.finish();
        return;
      }
      const secret = requireSecret("security_alerts", p.secrets);
      const client = clientFactory(secret);
      const { rows, watermarkNext } = await collectAlerts(
        client.fetchJson,
        state.startUrl,
        state.since,
        state.nowMs,
        DEFAULT_LAG_MS,
      );
      out.emit(buildWatermarkBatch("alerts", ALERT_SCHEMA, rows, watermarkNext));
      state.done = true;
    },
  });
}
