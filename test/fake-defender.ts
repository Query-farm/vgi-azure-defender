// A stateful fake of the Microsoft Graph security API — enough to prove the
// lagged-watermark cursor contract without a network: it serves canned JSON pages
// for `/security/incidents` (honoring `$expand=alerts($top=N)`) and
// `/security/alerts_v2`, filters by the `lastUpdateDateTime ge <since>` boundary,
// and pages via a `$skip` `@odata.nextLink` that graph-core's pager follows
// VERBATIM. No @removed / deltaLink here — closing an incident is a status FIELD
// change, exactly as the watermark archetype requires.
//
// Imports ONLY @vgi-azure/graph-core (for the FetchJson type), so the archetype
// test that uses it runs without the @query-farm SDK.

import type { FetchJson } from "@vgi-azure/graph-core";

const GRAPH = "https://graph.microsoft.com/v1.0";

export interface FakeAlert {
  id: string;
  title?: string;
  status?: string;
  severity?: string;
  category?: string;
  serviceSource?: string;
  detectionSource?: string;
  mitreTechniques?: string[];
  incidentId?: string;
  createdDateTime?: string;
  lastUpdateDateTime: string;
}

export interface FakeIncident {
  id: string;
  displayName?: string;
  status?: string;
  severity?: string;
  assignedTo?: string;
  tenantId?: string;
  incidentWebUrl?: string;
  createdDateTime?: string;
  lastUpdateDateTime: string;
  alerts?: FakeAlert[];
}

/** Parse the `lastUpdateDateTime ge <iso>` lower bound out of a `$filter` (stops at
 *  a space or a `)` so a combined `(… ge X) and (…)` filter parses cleanly). */
function sinceMsOf(filter: string): number {
  const m = /ge\s+([^\s)]+)/.exec(filter);
  return m ? Date.parse(m[1]!) : -Infinity;
}

export class FakeDefender {
  readonly incidents = new Map<string, FakeIncident>();
  readonly alerts = new Map<string, FakeAlert>();
  /** Every fetchJson call (asserts nextLink paging really re-fetches). */
  fetches = 0;
  /** The exact URLs requested, in order (asserts nextLink is followed verbatim). */
  readonly urls: string[] = [];

  constructor(private readonly pageSize: number = 100) {}

  upsertIncident(i: FakeIncident): void {
    this.incidents.set(i.id, { ...i });
  }
  upsertAlert(a: FakeAlert): void {
    this.alerts.set(a.id, { ...a });
  }

  fetch: FetchJson = async (url) => {
    this.fetches++;
    this.urls.push(url);
    const u = new URL(url);
    const filter = u.searchParams.get("$filter") ?? "";
    const sinceMs = sinceMsOf(filter);
    const skip = Number(u.searchParams.get("$skip") ?? "0");

    const isIncidents = u.pathname.endsWith("/security/incidents");

    if (isIncidents) {
      const expand = u.searchParams.get("$expand") ?? "";
      const topM = /alerts\(\$top=(\d+)\)/.exec(expand);
      const top = topM ? Number(topM[1]) : Number.POSITIVE_INFINITY;

      const all = [...this.incidents.values()]
        .filter((i) => Date.parse(i.lastUpdateDateTime) >= sinceMs) // `ge` boundary
        .sort((a, b) => Date.parse(a.lastUpdateDateTime) - Date.parse(b.lastUpdateDateTime));
      const slice = all.slice(skip, skip + this.pageSize).map((i) => {
        const alerts = i.alerts ?? [];
        return {
          ...i,
          alerts: alerts.slice(0, top), // capped inline set …
          alertsCount: alerts.length, // … but the server reports the FULL count → drives _alerts_truncated
        };
      });
      return this.page(u, slice, skip, all.length);
    }

    const all = [...this.alerts.values()]
      .filter((a) => Date.parse(a.lastUpdateDateTime) >= sinceMs)
      .sort((a, b) => Date.parse(a.lastUpdateDateTime) - Date.parse(b.lastUpdateDateTime));
    const slice = all.slice(skip, skip + this.pageSize).map((a) => ({ ...a }));
    return this.page(u, slice, skip, all.length);
  };

  private page(u: URL, value: unknown[], skip: number, total: number): Record<string, unknown> {
    const nextSkip = skip + this.pageSize;
    if (nextSkip < total) {
      const next = new URL(u.toString());
      next.searchParams.set("$skip", String(nextSkip));
      return { value, "@odata.nextLink": next.toString() };
    }
    return { value }; // final page — no nextLink, no deltaLink (watermark worker)
  }
}
