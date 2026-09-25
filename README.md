# pq-pulse

Checks whether a domain's TLS key exchange is post-quantum, and attributes the
TLS endpoint (CDN/WAF edge, cloud, or own infrastructure) from 7 evidence
slots across 5 evidence classes.

## Usage

```console
$ pq-pulse <domain>                      # text report to stdout
$ pq-pulse <domain> --json               # JSON
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
- 7 evidence slots — CNAME delegation, published IP ranges, certificate
  names, PTR, RDAP network registration, ASN and HTTP. `value` is the raw observation;
  evidence becomes a signal when it is deterministically attributed to
  either the scanned organization itself (own-zone CNAME/PTR, RDAP/ASN
  echoing the registrable label → `self (zone)`) or a known vendor
  (Cloudflare, Akamai, Imperva, Fastly, CloudFront, Myra, Link11,
  Google Cloud, Azure). Unresolved evidence is neutral and never counts
- `signals` — TLS-endpoint attribution: `self`, a known provider, or
  `unresolved`. Evidence classes: CNAME (DNS delegation), HTTP (actual edge
  processing), CERT, RANGE, and PTR+RDAP+ASN as one network-ownership class,
  so agreeing network evidence corroborates without inflating confidence.
  Contested attribution is reported as `candidates`. Two agreeing evidence
  classes = `confirmed`, one = `probable`

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
checked: 2026-09-25 17:31 +02:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.2
    KX           X25519
    symmetric    AES-256
    PQ           no

  termination
    provider     Akamai

  network
    IP           104.94.222.171
    PTR          a104-94-222-171.deploy.static.akamaitechnologies.com
    ASN          AS33905 AKAMAI-AMS
    RDAP         AKAMAI


MAIL
  no MX records


SUMMARY
  web            classical TLS at Akamai edge
  mail           no MX records
```

## Installation

From crates.io (requires Rust):

```console
$ cargo install pq-pulse
```

Or grab a prebuilt binary from [GitHub Releases](https://github.com/post-q/pq-pulse/releases)
(`pq-pulse-v<version>-<target>.tar.gz` for Linux x86_64/aarch64 and macOS aarch64).

## Requirements

- `dig` on PATH (CNAME/PTR/TXT lookups are shell-outs; origin ASN via
  Team Cymru DNS)
- network access; one HTTPS request per domain for HTTP evidence; vendor IP
  ranges are fetched once and cached 24 h in `$TMPDIR/pq-edge-ranges.json`

## Build

Requires Rust (stable, >= 1.85). If needed, install via [rustup](https://rustup.rs)

```console
$ cargo build --release
```

## Development

Commits follow the [Conventional Commits](https://www.conventionalcommits.org)
specification; CI rejects non-conforming messages, and the changelog is
generated from them with [git-cliff](https://git-cliff.org). Install
[cocogitto](https://docs.cocogitto.io) to validate locally:

```console
$ cargo install --locked cocogitto
$ cog install-hooks                  # commit-msg hook: cog verify
$ cog commit feat "add awesome thing" # instead of git commit -m "feat: ..."
```
