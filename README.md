# pq-pulse

Checks whether a domain's TLS key exchange is post-quantum, and attributes the
TLS endpoint (CDN/WAF edge, cloud, or own infrastructure) from five independent
evidence sources.

## Usage

```console
$ pq-pulse <domain>                      # text report to stdout
$ pq-pulse --format json <domain>        # JSON document
$ pq-pulse --list <list-file> <out-file> # batch, one JSON record per line
$ pq-pulse --list <list-file> <out-file> --format text --no-progress
```

`--json` is shorthand for `--format json`. Batch defaults to JSON records;
stdout shows a progress bar, `--no-progress` silences it (records still land in
the file, failed domains become inline error records and the run continues).
List files take one domain per line; `#` comments, blank lines and CRLF are
tolerated.

## What it reports

- `kx_group` — `X25519MLKEM768` means the key exchange is post-quantum
- `symmetric_alg` — AES128 / AES256 / CHACHA20-POLY1305
- five evidence slots — CNAME delegation, published IP ranges, certificate
  names, PTR, RDAP network registration. `value` is the raw observation;
  a slot becomes a **signal** when it matches a known vendor
  (Cloudflare, Akamai, Imperva, Fastly, CloudFront, Myra, Link11,
  Google Cloud, Azure)
- `signals` — per-scope aggregation: `infra` (who owns the network) and `edge`
  (who terminates TLS). Cloud PTR/RDAP proves hosting, not edge termination.
  Two agreeing evidence classes = `confirmed`, one = `probable`

| verdict | description |
| --- | --- |
| `pq_at_edge` | The public connection terminates at an identified edge/CDN/security provider, where post-quantum or hybrid key exchange is enabled. |
| `pq_cloud_hosted` | The service is hosted on infrastructure attributed to a public cloud provider, with post-quantum or hybrid key exchange enabled. |
| `pq_vendor_hosted` | The service is hosted on infrastructure attributed to a third-party provider, with post-quantum or hybrid key exchange enabled. |
| `pq_own_infra` | The service appears to terminate on infrastructure operated by the organization, with post-quantum or hybrid key exchange enabled. |
| `no_pq_edge` | The public connection terminates at an identified edge/CDN/security provider, but no post-quantum key exchange was observed. |
| `no_pq_cloud_hosted` | The service is hosted on infrastructure attributed to a public cloud provider, but no post-quantum key exchange was observed. |
| `no_pq_vendor_hosted` | The service is hosted on infrastructure attributed to a third-party provider, but no post-quantum key exchange was observed. |
| `no_pq_own_infra` | The service appears to terminate on infrastructure operated by the organization, but no post-quantum key exchange was observed. |

Text output (single domain):

```
domain:        citibankonline.pl
resolved_ip:   104.96.178.165
kx group:      X25519 (no PQ)
symmetric_alg: AES256

evidence:
  CNAME (none)
  RANGE (none)
  CERT  www.citi.com
  PTR   a104-96-178-165.deploy.static.akamaitechnologies.com -> Akamai
  RDAP  AKAMAI -> Akamai

signals:
  infra: Akamai (signals: 2, classes: 1, confidence: probable)
  edge:  Akamai (signals: 2, classes: 1, confidence: probable)

verdict:       no_pq_edge (The public connection terminates at an identified edge/CDN/security provider, but no post-quantum key exchange was observed.)
```

## Requirements

- `dig` on PATH (CNAME/PTR lookups are shell-outs)
- network access; vendor IP ranges are fetched once and cached 24 h in
  `$TMPDIR/pq-edge-ranges.json`

## Build

Requires Rust (stable, >= 1.85). If needed, install via [rustup](https://rustup.rs)

```console
$ cargo build --release
```
