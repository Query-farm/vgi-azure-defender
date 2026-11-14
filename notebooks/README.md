# Defender notebooks

[01 · Does an incident expansion contain all its alerts?](01_capped_alerts_and_complete_feeds.ipynb) compares capped nested alerts with the authoritative alert feed. It explains marker rows, count reconciliation and why a capped expansion is not a representative severity sample.

## Run All without an Azure account

Requirements: [uv](https://docs.astral.sh/uv/), [Bun](https://bun.sh/), Git, and network access for public worker/dependency downloads. Keep this whole directory together; no worker checkout or build is required.

```sh
cd notebooks
uv sync --locked
uv run --locked python execute.py
```

The notebook environment is locked to Haybarn 2.0.0rc11 and plotting/Jupyter dependencies. To register an optional editor kernel:

```sh
uv run --locked python -m ipykernel install --user --name vgi-azure-defender-notebooks --display-name "Python (vgi-azure-defender notebooks)"
```

Select it, use this directory as the working directory, and Restart Kernel → Run All. The headless runner creates its own temporary kernel registration. It preserves the last successful default on execution failure.

## Separate cap experiment

```sh
uv run --locked python execute.py --parameters '{"MAX_INLINE_ALERTS": 4}' --output-dir artifacts/cap-4
```

Overrides require a separate output directory; this copy includes branding, docs, environment, runner and fixture companions. Default cap 2; experiment cap 4. Generated logs, charts, experiment copies and environments are ignored by Git. Compare the fixture hash and authoritative counts; restore cap 2 for defaults.

## What is real, what is synthetic

The first visible ATTACH uses the published `github-auto://Query-farm/vgi-azure-defender@v0.4.0` release for credential-free metadata. The second literal command, `bun run defender_fixture.ts Query-farm/vgi-azure-defender 08d098b6991c98c6ac4fbeaa13c5e9caf12e5e7d fixture.json`, fetches the exact v0.4.0 source revision. The companion verifies Git HEAD, installs frozen Bun dependencies and caches by repository, commit and Bun version under `$XDG_CACHE_HOME/vgi-notebook-workers` (or `~/.cache`). Setup output goes to stderr; stdout carries Arrow. Upgrade both pins together and rerun default/experiment.

`defender_fixture.ts` imports the original `makeIncidentsFunction`, `makeAlertsFunction`, catalog and SDK. It injects the existing ClientFactory seam with the repository's shipped `test/FakeDefender`. Production schemas, mapping, pagination, truncation and watermark generation execute unchanged through VGI. `fixture.json` contains every synthetic input record; source order is deliberately biased. The fake pages at two objects per page and supports the lower-bound timestamp filter used here. It is not a general Microsoft Graph emulator.

The fixture's runtime network fetch is disabled, POST is rejected, and no MSAL client is constructed. A visibly dummy `azure_graph` secret satisfies function lookup; the fake client ignores it. Runtime request tracing uses a temporary local file that cleanup removes. Run All does not contact Azure, use a tenant, or claim live authentication/retry validation. All fixture event dates are January 1, 2024 UTC; execution time is separately reported.

## Optional live prerequisite (not part of Run All)

Live reads require a real `azure_graph` secret with Microsoft Entra client credentials and Graph application permissions `SecurityIncident.Read.All` and `SecurityAlert.Read.All`. Use the published connection with secrets provisioned outside saved notebook cells/outputs, following the [worker README](https://github.com/Query-farm/vgi-azure-defender#credentials). Do not replace the explicitly synthetic fixture silently: real feeds are changing, may contain sensitive records, and need their own bounded window and provenance. No live tenant was queried for this example.
