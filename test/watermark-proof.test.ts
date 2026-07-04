// THE reason vgi-azure-defender exists: prove the lastUpdateDateTime watermark is a
// durable, no-loss VGI scan cursor — the second graph-core archetype alongside
// directory's delta token. This test imports ONLY @vgi-azure/graph-core + the pure
// defender.ts driver + bun:test (NO @query-farm/* imports), so it runs without the
// SDK installed. It drives the FakeDefender security API end to end.

import { test, expect } from "bun:test";
import { clampWatermark, isoToMs, msToIso } from "@vgi-azure/graph-core";
import {
  collectIncidents,
  collectAlerts,
  buildIncidentsUrl,
  buildAlertsUrl,
  resolveSince,
  DEFAULT_LAG_MS,
  type DataRow,
} from "../src/defender.js";
import { FakeDefender } from "./fake-defender.js";

// A fixed clock so clampWatermark is deterministic. All fixture timestamps are
// expressed as an offset (minutes) from this NOW.
const NOW = Date.parse("2026-07-04T12:00:00.000Z");
const LAG = DEFAULT_LAG_MS; // 10 min
const min = (n: number) => n * 60 * 1000;
const at = (offsetMin: number) => msToIso(NOW + min(offsetMin)); // negative = in the past

const byId = (rows: DataRow[]) => new Map(rows.map((r) => [r.id, r]));
const kinds = (rows: DataRow[], k: DataRow["kind"]) => rows.filter((r) => r.kind === k);

function scanIncidents(fake: FakeDefender, since: string, maxAlerts = 50) {
  return collectIncidents(fake.fetch, buildIncidentsUrl(since, "", maxAlerts), since, maxAlerts, NOW, LAG);
}
function scanAlerts(fake: FakeDefender, since: string) {
  return collectAlerts(fake.fetch, buildAlertsUrl(since, ""), since, NOW, LAG);
}

test("FakeDefender window → incident+alert rows + a clamped watermark, and the cursor round-trips", async () => {
  const fake = new FakeDefender();
  fake.upsertIncident({ id: "inc-A", status: "active", severity: "high", lastUpdateDateTime: at(-60),
    alerts: [{ id: "al-A1", title: "a1", status: "active", lastUpdateDateTime: at(-60) }] });
  fake.upsertIncident({ id: "inc-B", status: "inProgress", severity: "medium", lastUpdateDateTime: at(-30),
    alerts: [{ id: "al-B1", title: "b1", status: "inProgress", lastUpdateDateTime: at(-30) }] });

  const since0 = resolveSince("", min(120), NOW); // empty since → bounded cold start at now − 2h
  const r1 = await scanIncidents(fake, since0);

  // Interleaved union: two incident rows + their two capped alert children.
  expect(kinds(r1.rows, "incident").map((r) => r.id).sort()).toEqual(["inc-A", "inc-B"]);
  expect(kinds(r1.rows, "alert").map((r) => r.id).sort()).toEqual(["al-A1", "al-B1"]);

  // maxSeen = newest lastUpdateDateTime (inc-B @ −30m); watermark = min(maxSeen,now) − lag = −40m.
  const expectedW1 = msToIso(clampWatermark(NOW + min(-30), LAG, NOW));
  expect(r1.watermarkNext).toBe(expectedW1);
  expect(r1.watermarkNext).toBe(at(-40));

  // Round-trip the cursor: a newer incident arrives; re-scan with `since := W1`.
  fake.upsertIncident({ id: "inc-C", status: "active", severity: "low", lastUpdateDateTime: at(-5),
    alerts: [{ id: "al-C1", title: "c1", status: "active", lastUpdateDateTime: at(-5) }] });
  const r2 = await scanIncidents(fake, r1.watermarkNext);
  const ids2 = kinds(r2.rows, "incident").map((r) => r.id).sort();

  // inc-C (new) is captured; inc-B (@ −30m ≥ W1 −40m) is re-read by the lag OVERLAP
  // (at-least-once, idempotent by id); inc-A (@ −60m < W1) is correctly excluded.
  expect(ids2).toEqual(["inc-B", "inc-C"]);
  expect(ids2).not.toContain("inc-A");
});

test("quiet tenant: watermark sits LAG behind maxSeen, never snaps to now", async () => {
  const fake = new FakeDefender();
  // maxSeen far below now − lag (a tenant with only old, settled incidents).
  fake.upsertIncident({ id: "inc-Q", status: "resolved", severity: "low", lastUpdateDateTime: at(-180) });

  const r = await scanIncidents(fake, resolveSince("", min(600), NOW));

  // clampWatermark applies the lag UNCONDITIONALLY: −180m − 10m = −190m, NOT now − lag.
  expect(isoToMs(r.watermarkNext)).toBe(NOW + min(-180) - LAG);
  expect(isoToMs(r.watermarkNext)).toBeLessThan(NOW - LAG); // did not snap forward to now − lag
  expect(r.watermarkNext).toBe(at(-190));
});

test("status change is emitted as a row, NOT a tombstone (§1: status over @removed)", async () => {
  const fake = new FakeDefender();
  fake.upsertIncident({ id: "inc-X", status: "active", severity: "high", assignedTo: "analyst@x", lastUpdateDateTime: at(-50),
    alerts: [{ id: "al-X1", title: "x1", status: "active", lastUpdateDateTime: at(-50) }] });

  const r1 = await scanIncidents(fake, resolveSince("", min(120), NOW));
  expect(byId(r1.rows).get("inc-X")!.status).toBe("active");

  // Analyst closes it: a FIELD change (status active → resolved) with a bumped stamp.
  fake.upsertIncident({ id: "inc-X", status: "resolved", severity: "high", assignedTo: "analyst@x", lastUpdateDateTime: at(-2),
    alerts: [{ id: "al-X1", title: "x1", status: "resolved", lastUpdateDateTime: at(-2) }] });

  const r2 = await scanIncidents(fake, r1.watermarkNext);
  const x = byId(r2.rows).get("inc-X");

  expect(x).toBeDefined();
  expect(x!.kind).toBe("incident"); // surfaces as a normal incident row …
  expect(x!.status).toBe("resolved"); // … whose status now reads resolved
  // There is NO tombstone / removed channel anywhere in the stream.
  expect(r2.rows.every((row) => row.kind === "incident" || row.kind === "alert")).toBe(true);
});

test("late arrival inside the lag window is re-read (justifies SAFETY_LAG; a naive ge-maxSeen would drop it)", async () => {
  const fake = new FakeDefender();
  fake.upsertAlert({ id: "al-1", title: "steady", status: "active", lastUpdateDateTime: at(-30) });

  const r1 = await scanAlerts(fake, resolveSince("", min(120), NOW));
  const maxSeen1 = NOW + min(-30);
  expect(r1.watermarkNext).toBe(at(-40)); // W1 = maxSeen − lag

  // A late-correlated alert materializes only now, but stamped INSIDE [W1, maxSeen1]
  // (−35m): earlier than the previous max, later than the persisted watermark.
  fake.upsertAlert({ id: "al-late", title: "late", status: "active", lastUpdateDateTime: at(-35) });
  expect(NOW + min(-35)).toBeLessThan(maxSeen1); // a naive `ge maxSeen` filter would SKIP it forever

  const r2 = await scanAlerts(fake, r1.watermarkNext); // `ge W1` re-scans the overlap
  expect(byId(r2.rows).has("al-late")).toBe(true); // the safety-lag overlap re-reads it
});

test("$expand=alerts cap → _alerts_truncated + fall back to security_alerts for completeness", async () => {
  const fake = new FakeDefender();
  fake.upsertIncident({ id: "inc-noisy", status: "active", severity: "high", lastUpdateDateTime: at(-20),
    alerts: [
      { id: "n1", lastUpdateDateTime: at(-20) },
      { id: "n2", lastUpdateDateTime: at(-20) },
      { id: "n3", lastUpdateDateTime: at(-20) },
    ] });

  const r = await scanIncidents(fake, resolveSince("", min(60), NOW), /*maxAlerts*/ 2);
  const inc = byId(r.rows).get("inc-noisy")!;
  expect(inc.kind).toBe("incident");
  expect((inc as { alertCount: number | null }).alertCount).toBe(3); // server-reported full count
  expect((inc as { alertsTruncated: boolean }).alertsTruncated).toBe(true); // cap hit → not the authoritative feed
  expect(kinds(r.rows, "alert").length).toBe(2); // only the capped set inline
});

test("nextLink paging is followed VERBATIM across pages", async () => {
  const fake = new FakeDefender(/*pageSize*/ 1); // 2 incidents → 2 pages
  fake.upsertIncident({ id: "p1", status: "active", lastUpdateDateTime: at(-40) });
  fake.upsertIncident({ id: "p2", status: "active", lastUpdateDateTime: at(-20) });

  const r = await scanIncidents(fake, resolveSince("", min(120), NOW));

  expect(kinds(r.rows, "incident").map((x) => x.id).sort()).toEqual(["p1", "p2"]);
  expect(fake.fetches).toBe(2); // page 1 (nextLink) → page 2 (final)
  expect(fake.urls[1]).toContain("%24skip=1"); // the server's opaque nextLink, replayed unchanged
});
