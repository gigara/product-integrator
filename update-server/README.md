# WSO2 Integrator Update Server

A Ballerina HTTP service that serves the signed update manifests for the WSO2
Integrator [component-wise update mechanism](../docs/update-mechanism-design.md).
It implements the read API the in-app updater calls, plus a token-guarded admin
endpoint for publishing manifests.

The server serves published manifest bytes **verbatim** so the detached cosign
signature stays valid — it never rewrites a manifest. Staged rollout and
compatibility resolution happen client-side against the manifest data (see the
design doc, §4.2). This keeps the server a thin, cacheable, signature-preserving
file server that can equally be replaced by static S3/CDN hosting.

## Requirements

- Ballerina Swan Lake `2201.13.4` (matches the runtime bundled with the product).

## Run

```bash
bal run
# or build a fat jar and run it:
bal build && java -jar target/bin/update_server.jar
```

The server listens on port `9600` by default and serves the sample manifests
under [`data/`](data).

```bash
curl http://localhost:9600/healthz
curl http://localhost:9600/api/v1/updates/stable/darwin/arm64/manifest.json
```

## Configuration

All settings are Ballerina `configurable` values ([`config.bal`](config.bal)).
Override via a `Config.toml`, environment variables, or `-C` CLI args:

| Setting | Default | Description |
|---|---|---|
| `port` | `9600` | HTTP listener port |
| `dataDir` | `data` | Root of the published manifest tree |
| `allowedChannels` | `["stable","beta","insider"]` | Channels the server will serve (also the channel path-segment allowlist) |
| `adminToken` | `""` | Bearer token for the publish endpoint; empty disables publishing |
| `cacheMaxAge` | `300` | `Cache-Control: max-age` (seconds) on artifact responses |

Example `Config.toml`:

```toml
port = 9600
dataDir = "/var/lib/wso2-integrator-updates"
allowedChannels = ["stable", "beta", "insider"]
adminToken = "change-me"
cacheMaxAge = 300
```

Or via CLI:

```bash
bal run -- -Cport=9711 -CadminToken=secret
```

> **TLS:** in production the service runs behind a TLS-terminating CDN / load
> balancer (per the design's S3 + CloudFront model). To terminate TLS in-process
> instead, add a `secureSocket` to the `http:Listener` in
> [`service.bal`](service.bal).

## API

### `GET /healthz`
Liveness/readiness probe. `200 {"status":"ok",...}`.

### `GET /api/v1/channels`
Lists channels that currently have published content. `200 {"channels":[...]}`.

### `GET /api/v1/updates/{channel}/{platform}/{arch}/manifest.json`
Returns the manifest for the given target.

- `platform` ∈ `darwin | linux | win32`, `arch` ∈ `x64 | arm64`, `channel` ∈ configured `allowedChannels`.
- Optional `?appVersion=<v>` query param (logged for telemetry; the full manifest is always returned so behavior matches static hosting).
- Sends a strong `ETag` (SHA-256 of the bytes) and `Cache-Control`. Send it back as `If-None-Match` for a `304 Not Modified`.
- `400` for an unsupported segment, `404` when nothing is published for that target.

### `GET /api/v1/updates/{channel}/{platform}/{arch}/manifest.json.sig`
### `GET /api/v1/updates/{channel}/{platform}/{arch}/manifest.json.pem`
The detached cosign signature and signing certificate that accompany the
manifest. The client verifies the manifest against these before trusting it.

### `PUT /api/v1/updates/{channel}/{platform}/{arch}/{manifest.json|.sig|.pem}` (admin)
Publishes an artifact. Disabled (`404`) unless `adminToken` is set; requires
`Authorization: Bearer <adminToken>`. `manifest.json` uploads are shape-validated
against the manifest schema before being written.

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
     --data-binary @manifest.json \
     http://localhost:9600/api/v1/updates/stable/darwin/arm64/manifest.json
```

## Manifest layout on disk

```
data/api/v1/updates/<channel>/<platform>/<arch>/
    manifest.json
    manifest.json.sig
    manifest.json.pem
```

The bundled samples ([`data/`](data)) correspond to the example in the design
doc. Their `.sig`/`.pem` files are **placeholders** — real signatures are
produced by CI.

## Test

```bash
bal test
```

## CI integration

The publishing pipeline (`.github/workflows/build-and-release.yml`, per the
design doc §D7) is expected to:

1. Build the per-component artifacts (VSIXes, Ballerina runtime, JRE, ICP, installers) and cosign-sign each one.
2. Render `manifest.json` per `(channel, platform, arch)` from `ci/build/component-versions.properties` with computed SHA-256s and artifact URLs.
3. cosign-sign the manifest itself (producing `manifest.json.sig` / `.pem`).
4. Publish the manifest tree — either to the object store this server reads from (`dataDir`), or directly through the admin `PUT` endpoint.

Promotion runs down the channel ladder (`insider → beta → stable`) behind
manual-approval jobs; each channel keeps its own monotonic `sequence`.
