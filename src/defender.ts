// The defender watermark driver — pure logic over graph-core, no SDK / no network.
//
// This is the lagged-watermark analogue of directory's collectDelta: it drains a
// `/security/incidents` (with `$expand=alerts`) or `/security/alerts_v2` scan to
// completion by paging `@odata.nextLink` VERBATIM, folds a client-side max over
// `lastUpdateDateTime` (never trusting page order, so `$orderby` is decorative —
// graph-core-SPEC §C / watermark.ts foldMaxSeen), then computes the next watermark
// through the CANONICAL graph-core clampWatermark (`min(maxSeen, now) - lag`).
//
// Cross-scan state is a single ISO-8601 string (`since` in / `_watermark_next`
// out). The boundary filter is `ge` (never `gt`) so the safety-lag overlap window
// re-reads late-correlated rows; the caller's apply is idempotent by `id`, giving
// at-least-once capture + exactly-once effect. There is NO delta token and NO
// `@removed` tombstone here: closing an incident/alert is a `status` FIELD change,
// which we emit and let speak (SPEC §1).

import {
  paginate,
  clampWatermark,
  isoToMs,
  msToIso,
  foldMaxSeen,
  type FetchJson,
} from "@vgi-azure/graph-core";

export const GRAPH = "https://graph.microsoft.com/v1.0";

/** Default safety lag: 10 minutes. Lag-zero is a data-loss bug, not a tuning
 *  option (SPEC §2.1) — the overlap window collapses and late-correlated rows are
 *  dropped forever. Callers may widen it (redundant re-reads, bounded/harmless). */
export const DEFAULT_LAG_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// Row shapes (plain, fully serializable — no Date, no RecordBatch, no socket).
// ---------------------------------------------------------------------------

export interface IncidentRow {
  kind: "incident";
  id: string;
  incidentId: string; // self
  displayName: string | null;
  status: string | null;
  severity: string | null;
  classification: string | null;
  determination: string | null;
  assignedTo: string | null; // analyst PII (SPEC §1.1)
  tenantId: string | null;
  incidentWebUrl: string | null;
  alertCount: number | null;
  alertsTruncated: boolean; // capped $expand=alerts($top=N) did not return the full set
  createdDateTime: string | null;
  lastUpdateDateTime: string | null;
}

export interface AlertRow {
  kind: "alert";
  id: string;
  incidentId: string | null; // parent (null for a standalone alerts_v2 scan)
  title: string | null;
  status: string | null;
  severity: string | null;
  classification: string | null;
  determination: string | null;
  category: string | null;
  serviceSource: string | null;
  detectionSource: string | null;
  mitreTechniques: string[] | null;
  firstActivityDateTime: string | null;
  lastActivityDateTime: string | null;
  createdDateTime: string | null;
  lastUpdateDateTime: string | null;
}

export type DataRow = IncidentRow | AlertRow;

export interface WatermarkResult {
  rows: DataRow[];
  /** The ISO-8601 watermark to persist as `since` for the next scan (clamped). */
  watermarkNext: string;
}

// ---------------------------------------------------------------------------
// URL builders. `$orderby=lastUpdateDateTime` is a query-shape optimization the
// safety math does NOT depend on (foldMaxSeen re-maxes the whole window), so it is
// SAFE to drop if an endpoint rejects it — graph-core owns the probe/inject/reject
// (SPEC §2.3). We still request it; the boundary filter is always `ge`.
// ---------------------------------------------------------------------------

function andFilter(since: string, extra: string): string {
  const base = `lastUpdateDateTime ge ${since}`; // `ge`, never `gt` (SPEC §2.1)
  return extra ? `(${base}) and (${extra})` : base;
}

export function buildIncidentsUrl(since: string, filter: string, maxAlerts: number): string {
  const params = new URLSearchParams();
  params.set("$filter", andFilter(since, filter));
  params.set("$orderby", "lastUpdateDateTime");
  // Bound the fan-out: a naked $expand=alerts returns every child inline on one
  // page (unbounded payload, blows the CF subrequest budget — SPEC §2). Cap it.
  params.set("$expand", `alerts($top=${maxAlerts})`);
  return `${GRAPH}/security/incidents?${params.toString()}`;
}

export function buildAlertsUrl(since: string, filter: string): string {
  const params = new URLSearchParams();
  params.set("$filter", andFilter(since, filter));
  params.set("$orderby", "lastUpdateDateTime");
  return `${GRAPH}/security/alerts_v2?${params.toString()}`;
}

/** Resolve an empty `since` to a BOUNDED cold start at `now - lookback` (SPEC §2
 *  step 1) — never "all history". A caller opts into a full backfill by passing an
 *  explicit old `since` (or lookback '0'). */
export function resolveSince(since: string, lookbackMs: number, nowMs: number): string {
  if (since) return since;
  return msToIso(nowMs - lookbackMs);
}

// ---------------------------------------------------------------------------
// Field mappers (raw Graph object -> plain row). camelCase Graph fields in,
// typed row out; missing fields become null.
// ---------------------------------------------------------------------------

function str(v: unknown): string | null {
  return v == null ? null : String(v);
}

export function toAlertRow(obj: Record<string, unknown>, parentIncidentId: string | null): AlertRow {
  const mitre = obj.mitreTechniques;
  return {
    kind: "alert",
    id: String(obj.id ?? ""),
    incidentId: parentIncidentId ?? (obj.incidentId != null ? String(obj.incidentId) : null),
    title: str(obj.title),
    status: str(obj.status),
    severity: str(obj.severity),
    classification: str(obj.classification),
    determination: str(obj.determination),
    category: str(obj.category),
    serviceSource: str(obj.serviceSource),
    detectionSource: str(obj.detectionSource),
    mitreTechniques: Array.isArray(mitre) ? mitre.map((t) => String(t)) : null,
    firstActivityDateTime: str(obj.firstActivityDateTime),
    lastActivityDateTime: str(obj.lastActivityDateTime),
    createdDateTime: str(obj.createdDateTime),
    lastUpdateDateTime: str(obj.lastUpdateDateTime),
  };
}

/** Map one raw incident + its (capped) expanded alerts into an incident row and
 *  interleaved alert child rows. `alertsTruncated` is true when the incident's
 *  real alert count exceeds the returned/capped set — consumers MUST then fall
 *  back to `security_alerts` for completeness (SPEC §2). */
export function toIncidentRows(obj: Record<string, unknown>, maxAlerts: number): DataRow[] {
  const id = String(obj.id ?? "");
  const alerts = Array.isArray(obj.alerts) ? (obj.alerts as Record<string, unknown>[]) : [];
  // Prefer a server-reported count when present; else fall back to the inline set.
  const reported = obj.alertsCount ?? obj.alertCount;
  const realCount = reported != null ? Number(reported) : alerts.length;
  const truncated = realCount > maxAlerts || alerts.length > maxAlerts;

  const incident: IncidentRow = {
    kind: "incident",
    id,
    incidentId: id,
    displayName: str(obj.displayName),
    status: str(obj.status),
    severity: str(obj.severity),
    classification: str(obj.classification),
    determination: str(obj.determination),
    assignedTo: str(obj.assignedTo),
    tenantId: str(obj.tenantId),
    incidentWebUrl: str(obj.incidentWebUrl),
    alertCount: Number.isFinite(realCount) ? realCount : null,
    alertsTruncated: truncated,
    createdDateTime: str(obj.createdDateTime),
    lastUpdateDateTime: str(obj.lastUpdateDateTime),
  };

  const rows: DataRow[] = [incident];
  for (const a of alerts.slice(0, maxAlerts)) rows.push(toAlertRow(a, id));
  return rows;
}

// ---------------------------------------------------------------------------
// The drains. Each pages a start URL to completion, collects rows, folds the
// client-side max over lastUpdateDateTime, and returns the clamped watermark.
//
// Loss-safety lives in the CALLER (SPEC §2): persist `watermarkNext` only AFTER
// the rows are durably applied. On crash the caller still holds the old `since`;
// the next scan replays the same `ge <since>` window — absorbed idempotently by
// upsert-by-id. A ThrottledExhausted from graph-core mid-scan likewise leaves the
// old `since` intact.
// ---------------------------------------------------------------------------

/** Fold each row's lastUpdateDateTime into the running max-seen (order-independent). */
function foldRows(maxSeenMs: number, rows: DataRow[]): number {
  const times: number[] = [];
  for (const r of rows) {
    if (r.lastUpdateDateTime) times.push(isoToMs(r.lastUpdateDateTime));
  }
  return foldMaxSeen(maxSeenMs, times);
}

async function drain(
  fetchJson: FetchJson,
  startUrl: string,
  mapPage: (obj: Record<string, unknown>) => DataRow[],
  sinceMs: number,
  nowMs: number,
  lagMs: number,
): Promise<WatermarkResult> {
  const rows: DataRow[] = [];
  // Seed maxSeen from `since` so a quiet page (no rows) still clamps sensibly
  // relative to the window we asked for, not to -Infinity.
  let maxSeenMs = sinceMs;
  for await (const page of paginate<Record<string, unknown>>(fetchJson, startUrl)) {
    const pageRows: DataRow[] = [];
    for (const obj of page.value) pageRows.push(...mapPage(obj));
    rows.push(...pageRows);
    maxSeenMs = foldRows(maxSeenMs, pageRows);
    // nextLink is followed VERBATIM inside paginate — never reconstructed.
  }
  const watermarkNext = msToIso(clampWatermark(maxSeenMs, lagMs, nowMs));
  return { rows, watermarkNext };
}

export function collectIncidents(
  fetchJson: FetchJson,
  startUrl: string,
  since: string,
  maxAlerts: number,
  nowMs: number,
  lagMs: number = DEFAULT_LAG_MS,
): Promise<WatermarkResult> {
  return drain(fetchJson, startUrl, (obj) => toIncidentRows(obj, maxAlerts), isoToMs(since), nowMs, lagMs);
}

export function collectAlerts(
  fetchJson: FetchJson,
  startUrl: string,
  since: string,
  nowMs: number,
  lagMs: number = DEFAULT_LAG_MS,
): Promise<WatermarkResult> {
  return drain(fetchJson, startUrl, (obj) => [toAlertRow(obj, null)], isoToMs(since), nowMs, lagMs);
}
