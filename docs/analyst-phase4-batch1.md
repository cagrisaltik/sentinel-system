# Analyst Phase 4 Batch 1

## Frontend assets

The Analyst dashboard uses locally served ApexCharts 7.8.0 and Grid.js 6.2.0 assets. These are the package versions returned by the unpinned CDN package URLs when resolved on 2026-10-05. Package tarballs were retrieved from the npm registry by exact version; registry SHA-512 integrity values:

- `apexcharts@7.8.0`: `sha512-UxzR7IDXs3HDaOoxTsdn7L2dw9TdYp347uiU7WvjKuzCQqODmO7l63rxMmLwtbYrZPd+0Vd7v5VINzJgPyqmIw==`
- `gridjs@6.2.0`: `sha512-EAGGfHjyEXWh12Txs6DjTGnWTo226wbowtMrLI+yNZQaJpvs0m7yDcyM7r+D4RA7rZQVj/cfmwEaRz/rlxg8LA==`

| Local file | Exact package asset |
| --- | --- |
| `web/analyst/assets/apexcharts.min.js` | `apexcharts@7.8.0/dist/apexcharts.min.js` |
| `web/analyst/assets/gridjs.min.js` | `gridjs@6.2.0/dist/gridjs.production.min.js` |
| `web/analyst/assets/gridjs.min.css` | `gridjs@6.2.0/dist/theme/mermaid.min.css` |

Grid.js's production minified file is byte-identical to the `dist/gridjs.umd.js` asset named by the previous unpinned URL. The upstream license files are retained beside the vendored files as `LICENSE.apexcharts.txt` and `LICENSE.gridjs.txt`.

## MySQL transport

TCP and other non-Unix MySQL transports require an explicit `tls=true` in `DATABASE_URL`. The application replaces that option with a verified TLS configuration using system trust roots, TLS 1.2 or newer, and hostname verification. `tls=false`, `skip-verify`, `preferred`, missing TLS configuration, and plaintext fallback are rejected before opening the pool.

For an internal CA, set `DATABASE_TLS_CA_FILE` to a PEM file containing the CA certificate. That CA is added to the system trust pool; the server certificate and hostname remain verified. A local MySQL Unix socket may omit `tls` because the connection stays on the local socket transport. Insecure TLS modes are rejected for Unix socket DSNs as well.

## Login throttling

Login failures are counted by source IP, source IP plus normalized username, and normalized username across IPs. Username normalization is trim plus lowercase, matching the existing login key behavior. Limits are temporary and expire through the configured window/cooldown cleanup. `LOGIN_ACCOUNT_MAX_ATTEMPTS` defaults to 10 per account window; `LOGIN_MAX_ATTEMPTS` and `LOGIN_IDENTITY_MAX_ATTEMPTS` keep their existing defaults.

The in-memory login limiter is capped at 20,000 keys. It reuses space by evicting the least-recently-seen entries that are not currently cooling down; active cooldown entries are retained. If every available entry is cooling down, new keys receive the same generic rate-limit response without allocating memory. Stale entries are also removed by the existing cleanup loop.

## Trusted reverse proxies

Set `TRUSTED_PROXY_CIDRS` to a comma-separated list of canonical CIDRs, for example `10.20.0.0/16,2001:db8:abcd::/48`. When unset, Analyst uses the direct peer address. Analyst only reads `X-Forwarded-For` when the direct peer is within a configured trusted CIDR. It walks the parsed chain from the right and stops at the first untrusted address; malformed chains fall back to the direct peer. Empty entries, duplicates, malformed CIDRs, and CIDRs with host bits set are rejected at startup.
