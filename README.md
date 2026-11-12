# vgi-azure-defender

A [VGI](https://query.farm) worker (**Microsoft Defender Security**) for DuckDB. Microsoft 365 Defender / Microsoft Sentinel security incidents and alerts as incremental (watermark) DuckDB table functions over the Microsoft Graph security API: `security_incidents` (incidents with their correlated alerts) and `security_alerts` (the authoritative `alerts_v2` feed). Each scan returns the rows whose `lastUpdateDateTime` advanced since the last cursor plus a single marker row (`_row_kind = 'marker'`) whose `_watermark_next` is the cursor to persist and pass back as `since`. Call with no arguments for a bounded cold start (default 30 days). A credential-free `feeds` view lists the available feeds.

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-azure-defender/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'azure' AS azure (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-azure-defender@v0.4.0');

-- Bind security_incidents and expose its result columns (credential-free; drop LIMIT 0
-- and attach an azure_graph secret to sync real incidents)
SELECT id, incident_id, display_name, status, severity, _row_kind, _watermark_next FROM azure.main.security_incidents() LIMIT 0;

-- Bind security_alerts and expose its result columns (credential-free; attach an
-- azure_graph secret to sync real alerts)
SELECT id, incident_id, title, status, severity, category, _row_kind, _watermark_next FROM azure.main.security_alerts() LIMIT 0;
```

The examples are credential-free `LIMIT 0` bind probes: they check that each function binds and show its result columns without calling Azure. To pull real rows, create an `azure_graph` secret (see [Credentials](#credentials)) and drop the `LIMIT 0`.

All the Query Farm Azure workers use the catalog name `azure`. To attach more than one in the same session, give each its own alias (for example `ATTACH 'azure' AS azure_defender (...)`) and qualify queries with that alias instead of `azure`.

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64). `github-auto://` needs an explicit release tag; change `@v0.4.0` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'azure' AS azure (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-azure-defender:0.4.0');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-azure-defender/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build and test the worker yourself, see [Development](#development).

## Credentials

Live queries authenticate with an `azure_graph` secret holding app-only Microsoft Entra client credentials for a service principal: `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET` (the client secret is redacted when secrets are listed). The worker registers the `azure_graph` secret type when it is attached, so create the secret after the `ATTACH`:

```sql
ATTACH 'azure' AS azure (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-azure-defender@v0.4.0');
CREATE SECRET azure_sp (TYPE azure_graph, TENANT_ID '<tenant-guid>', CLIENT_ID '<app-guid>', CLIENT_SECRET '<secret>');
```

For this worker the service principal needs the Microsoft Graph application permissions `SecurityIncident.Read.All` and `SecurityAlert.Read.All`.

## Development

Requires [Bun](https://bun.sh). `bun install` also fetches the shared `@vgi-azure/graph-core` package from GitHub.

```bash
bun install && bun test
bun run typecheck
```

To attach a local checkout, point `LOCATION` at the launch wrapper:

```sql
ATTACH 'azure' AS azure (TYPE vgi, LOCATION '/path/to/vgi-azure-defender/bin/vgi-azure-defender-worker');
```

## License

MIT. See [LICENSE](LICENSE).
