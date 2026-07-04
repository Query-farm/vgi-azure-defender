// Arrow output schemas + row->batch mapping for the two defender collections.
//
// `security_incidents` returns ONE flat UNION Arrow schema (INCIDENT_SCHEMA, SPEC
// §4.1) whose row stream interleaves three `_row_kind`s: `incident`, `alert`
// (from the capped $expand=alerts children, carrying `incident_id` = parent), and
// exactly one strict `marker`. Because Arrow batches are columnar and homogeneous,
// incident-only and alert-only fields coexist as NULLABLE columns; each row
// populates only its kind's columns and leaves the rest null.
//
// `security_alerts` returns the SAME schema minus the incident-only columns
// (display_name, assigned_to, tenant_id, incident_web_url, alert_count,
// _alerts_truncated) — only `_row_kind ∈ {alert, marker}`.
//
// Timestamp columns are emitted as Utf8 ISO-8601 strings (not Arrow timestamp),
// keeping every cell string-serializable and matching the marker/watermark's ISO
// shape — the same all-nullable-string discipline the directory template uses.
// `mitre_techniques` is the one non-scalar: List<Utf8>.

import { Schema, Field, Utf8, Bool, Int32, List } from "@query-farm/apache-arrow";
import { batchFromColumns } from "@query-farm/vgi";
import { ROW_KIND, MARKER, WATERMARK_NEXT } from "@vgi-azure/graph-core";
import type { DataRow, IncidentRow, AlertRow } from "./defender.js";

function utf8(name: string): Field {
  return new Field(name, new Utf8(), true);
}

// Ordered column list for the UNION schema. `incidentOnly` columns are dropped
// from the alerts-only schema. The `_row_kind` and `_watermark_next` control
// columns close every schema (graph-core marker contract, §D/§4.1).
interface ColDef {
  name: string;
  field: Field;
  incidentOnly?: boolean;
}

const COLUMNS: ColDef[] = [
  { name: "id", field: utf8("id") },
  { name: "incident_id", field: utf8("incident_id") },
  { name: "display_name", field: utf8("display_name"), incidentOnly: true },
  { name: "title", field: utf8("title") },
  { name: "status", field: utf8("status") },
  { name: "severity", field: utf8("severity") },
  { name: "classification", field: utf8("classification") },
  { name: "determination", field: utf8("determination") },
  { name: "assigned_to", field: utf8("assigned_to"), incidentOnly: true }, // analyst PII (§1.1)
  { name: "tenant_id", field: utf8("tenant_id"), incidentOnly: true },
  { name: "incident_web_url", field: utf8("incident_web_url"), incidentOnly: true },
  { name: "alert_count", field: new Field("alert_count", new Int32(), true), incidentOnly: true },
  { name: "_alerts_truncated", field: new Field("_alerts_truncated", new Bool(), true), incidentOnly: true },
  { name: "category", field: utf8("category") },
  { name: "service_source", field: utf8("service_source") },
  { name: "detection_source", field: utf8("detection_source") },
  { name: "mitre_techniques", field: new Field("mitre_techniques", new List(utf8("item")), true) },
  { name: "first_activity_datetime", field: utf8("first_activity_datetime") },
  { name: "last_activity_datetime", field: utf8("last_activity_datetime") },
  { name: "created_datetime", field: utf8("created_datetime") },
  { name: "last_update_datetime", field: utf8("last_update_datetime") },
];

const CONTROL: Field[] = [utf8(ROW_KIND), utf8(WATERMARK_NEXT)];

/** Column kind: whether this function includes the incident-only columns. */
export type SchemaKind = "incidents" | "alerts";

function colsFor(kind: SchemaKind): ColDef[] {
  return kind === "incidents" ? COLUMNS : COLUMNS.filter((c) => !c.incidentOnly);
}

export function schemaFor(kind: SchemaKind): Schema {
  return new Schema([...colsFor(kind).map((c) => c.field), ...CONTROL]);
}

/** The interleaved UNION schema for `security_incidents` (incident ⊕ alert ⊕ marker). */
export const INCIDENT_SCHEMA = schemaFor("incidents");
/** The alert-only schema for `security_alerts` (alert ⊕ marker). */
export const ALERT_SCHEMA = schemaFor("alerts");

// ---------------------------------------------------------------------------
// Row -> per-column value extraction. Each row kind knows only its own columns;
// every other column contributes null, which is how the union stays homogeneous.
// ---------------------------------------------------------------------------

function incidentValue(r: IncidentRow, col: string): unknown {
  switch (col) {
    case "id": return r.id;
    case "incident_id": return r.incidentId;
    case "display_name": return r.displayName;
    case "status": return r.status;
    case "severity": return r.severity;
    case "classification": return r.classification;
    case "determination": return r.determination;
    case "assigned_to": return r.assignedTo;
    case "tenant_id": return r.tenantId;
    case "incident_web_url": return r.incidentWebUrl;
    case "alert_count": return r.alertCount;
    case "_alerts_truncated": return r.alertsTruncated;
    case "created_datetime": return r.createdDateTime;
    case "last_update_datetime": return r.lastUpdateDateTime;
    default: return null; // alert-only columns (title, category, mitre_*, …) are null on an incident row
  }
}

function alertValue(r: AlertRow, col: string): unknown {
  switch (col) {
    case "id": return r.id;
    case "incident_id": return r.incidentId;
    case "title": return r.title;
    case "status": return r.status;
    case "severity": return r.severity;
    case "classification": return r.classification;
    case "determination": return r.determination;
    case "category": return r.category;
    case "service_source": return r.serviceSource;
    case "detection_source": return r.detectionSource;
    case "mitre_techniques": return r.mitreTechniques;
    case "first_activity_datetime": return r.firstActivityDateTime;
    case "last_activity_datetime": return r.lastActivityDateTime;
    case "created_datetime": return r.createdDateTime;
    case "last_update_datetime": return r.lastUpdateDateTime;
    default: return null; // incident-only columns are null on an alert row
  }
}

function valueFor(r: DataRow, col: string): unknown {
  return r.kind === "incident" ? incidentValue(r, col) : alertValue(r, col);
}

/**
 * Build one Arrow batch: the data rows (each with `_row_kind` = 'incident'|'alert',
 * `_watermark_next` null) followed by exactly ONE strict marker row
 * (`_row_kind='marker'`, `_watermark_next` = the clamped ISO watermark, EVERY
 * business column null — SPEC §4.1). Consumers read data via
 * `WHERE _row_kind <> 'marker'` (equivalently `_watermark_next IS NULL`) and the
 * cursor from the single marker row. Emitting N+1 rows in one batch keeps the
 * marker atomic with its data. There is NO authoritative per-row watermark on data
 * rows — the committed maxSeen-lag is known only after the final page (§D).
 */
export function buildWatermarkBatch(kind: SchemaKind, schema: Schema, rows: DataRow[], watermarkNext: string) {
  const defs = colsFor(kind);
  const cols: Record<string, unknown[]> = {};
  for (const c of defs) cols[c.name] = [];
  cols[ROW_KIND] = [];
  cols[WATERMARK_NEXT] = [];

  for (const r of rows) {
    for (const c of defs) cols[c.name]!.push(valueFor(r, c.name));
    cols[ROW_KIND]!.push(r.kind); // 'incident' | 'alert' — the status field speaks; never a tombstone (§1)
    cols[WATERMARK_NEXT]!.push(null);
  }

  // The single strict marker row: all business columns null, control set.
  for (const c of defs) cols[c.name]!.push(null);
  cols[ROW_KIND]!.push(MARKER);
  cols[WATERMARK_NEXT]!.push(watermarkNext);

  return batchFromColumns(cols, schema);
}
