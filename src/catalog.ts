// The `azure` catalog descriptor + the azure_graph secret type for vgi-azure-defender.
// The secret shape is the app-only client-credentials freeze that directory owns
// (graph-core-SPEC §A); defender re-declares the identical shape here so every
// catalog advertises the same `azure_graph` type independently.

import { Schema, Field, Utf8 } from "@query-farm/apache-arrow";
import type { CatalogDescriptor, SecretTypeDescriptor, VgiFunction } from "@query-farm/vgi";

export const AZURE_GRAPH_SECRET: SecretTypeDescriptor = {
  name: "azure_graph",
  description: "Microsoft Entra app-only (client-credentials) credentials for Microsoft Graph",
  schema: new Schema([
    new Field("tenant_id", new Utf8(), true),
    new Field("client_id", new Utf8(), true),
    new Field("client_secret", new Utf8(), true, new Map([["redact", "true"]])),
  ]),
};

export function makeCatalog(functions: VgiFunction[]): CatalogDescriptor {
  return {
    name: "azure",
    defaultSchema: "main",
    comment:
      "Microsoft 365 Defender / Sentinel incidents & alerts via Microsoft Graph security API — " +
      "lastUpdateDateTime watermark cursor (safety-lag, ge boundary, dedup-by-id). vgi-azure-defender",
    sourceUrl: "https://query.farm",
    secretTypes: [AZURE_GRAPH_SECRET],
    schemas: [{ name: "main", functions }],
  };
}
