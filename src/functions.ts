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
