// vgi-azure-defender stdio worker entry. DuckDB spawns this and ATTACHes it:
//   ATTACH 'def' AS def (TYPE vgi, LOCATION '/path/to/worker.ts');
//   CREATE SECRET g (TYPE azure_graph, TENANT_ID '…', CLIENT_ID '…', CLIENT_SECRET '…');
//   SELECT * FROM def.security_incidents();                        -- bounded cold start (now − lookback)
//   SELECT * FROM def.security_incidents(since := '<_watermark_next>'); -- incremental
//   SELECT * FROM def.security_alerts(since := '<_watermark_next>');    -- authoritative alert feed
//
// The AUDIENCE is pinned to `graph` in the clientFactory below (graph-core-SPEC §A):
// Defender is Graph-only, and the 3-tuple (tenant_id, client_id, 'graph') cache key
// guarantees an ARM / Log-Analytics token is never served here (and vice-versa).

import { Worker, ReadOnlyCatalogInterface, FunctionRegistry } from "@query-farm/vgi";
import { TokenCache, makeGraphClient, type Fetch } from "@vgi-azure/graph-core";
import { makeMsalMinter } from "@vgi-azure/node-auth";
import { makeIncidentsFunction, makeAlertsFunction, type ClientFactory } from "./functions.js";
import { makeCatalog } from "./catalog.js";

const cache = new TokenCache(makeMsalMinter());

const clientFactory: ClientFactory = (secret: Record<string, unknown>) =>
  makeGraphClient({
    fetch: globalThis.fetch as unknown as Fetch,
    cache,
    cred: {
      tenantId: String(secret.tenant_id ?? ""),
      clientId: String(secret.client_id ?? ""),
      clientSecret: secret.client_secret != null ? String(secret.client_secret) : undefined,
    },
    audience: "graph", // Defender rides the Graph audience only (SPEC §3).
  });

const functions = [makeIncidentsFunction(clientFactory), makeAlertsFunction(clientFactory)];

const registry = new FunctionRegistry();
for (const f of functions) registry.register(f);

const catalogInterface = new ReadOnlyCatalogInterface(makeCatalog(functions), registry);

new Worker({ functions, catalogInterface }).run();
