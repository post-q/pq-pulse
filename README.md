# pq-pulse

Checks whether a domain's TLS key exchange is post-quantum. It probes:
- for the public web endpoint (443)
- for its mail transport (every MX record on TCP/25, 587 and 465)

and attributes the underlying infrastructure (organization,
third-party provider, or unknown) plus, independently, whether the TLS
endpoint is a provider edge/CDN/WAF.

## Usage

```console
$ pq-pulse <domain>                      # text report to stdout
$ pq-pulse <domain> --json               # JSON
$ pq-pulse --list <list-file> <out-file> # batch, one JSON record per line
$ pq-pulse --list <list-file> <out-file> --format text --no-progress
$ pq-pulse --list <list-file> <out-file> --jobs 8
```

`--json` is shorthand for `--format json`. Batch defaults to JSON records;
stdout shows a progress bar, `--no-progress` silences it (records still land in
the file, failed domains become inline error records and the run continues).
List files take one domain per line; `#` comments, blank lines and CRLF are
tolerated.

## What it reports

```
$ ./pq-pulse nbp.pl

nbp.pl
checked: 2026-09-28 14:40 +02:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-128
    PQ           yes

  termination
    provider     Imperva

  network
    IP           45.223.164.250
    PTR          -
    ASN          AS19551 INCAPSULA
    RDAP         THALES-IMPERVA-NA4-AGG-45-223


MAIL
  MX 10  mx1r.nbp.pl

    25/tcp       unreachable
    587/tcp      unreachable
    465/tcp      unreachable

    network
      IP         195.85.196.53
      PTR        mx1r.nbp.pl
      ASN        AS21328 NBP-AS
      RDAP       NBPNET
    attribution
      infrastructure  ambiguous
      operator   -
      provider   -
      confidence  mixed

  MX 10  mx1c.nbp.pl

    25/tcp       unreachable
    587/tcp      unreachable
    465/tcp      unreachable

    network
      IP         193.109.212.53
      PTR        mx1c.nbp.pl
      ASN        AS21328 NBP-AS
      RDAP       NBPNET
    attribution
      infrastructure  ambiguous
      operator   -
      provider   -
      confidence  mixed


SUMMARY
  web            PQ TLS at Imperva edge
  mail           MX discovered; SMTP/25 unreachable from probe
```

- `TLS` / `KX` / `symmetric` / `PQ` — negotiated protocol version, key-exchange
  group and symmetric suite. `X25519MLKEM768` is the post-quantum hybrid
- 7 evidence slots — CNAME delegation chain, matched provider IP range,
  certificate names (CN + SANs), HTTP edge headers, PTR, RDAP network
  registration, origin ASN
- `infrastructure` — who owns the network the endpoint sits on, from
  independent signal classification against the scan target's identity
  (derived once from the domain, e.g. `mbank.pl` → `mbank`): CNAME and PTR
  zone membership, RDAP/AS identity match (normalized, with bounded
  prefix/subset rules — no unrestricted substrings), certificate subject
  names, vendor IP ranges. Signals are counted without weights:
  ≥ 2 agreeing target signals (or ≥ 2 third-party signals) attribute
  firmly, a lone signal leans (`possibly-*`), a mix of both sides is
  `ambiguous`, nothing stays `unknown`. Confidence follows the count:
  `none`, `weak`, `likely`, `confirmed`; contested evidence reports
  `mixed`. The `provider` name is observed, not looked up from a list:
  vendor aliases where known (Cloudflare, Akamai, Imperva, Fastly,
  CloudFront, …), otherwise the identity agreed between the AS name and
  the RDAP organization (e.g. `OVH` ↔ `OVH-DEDICATED-FO`)
- `termination` — whether the TLS endpoint is a provider edge, independent of
  who owns the network: provider identity alone is never role evidence
  (an OVH ASN is hosting, an AWS ASN is not automatically edge). Edge
  evidence: CNAME into a vendor edge namespace, IP in a documented edge
  range, vendor HTTP edge headers, certificate names in an edge namespace,
  an edge-vendor RDAP/AS name. Two independent classes → `edge`, one strong
  class → `likely_edge`, otherwise `unproven`
- `MAIL` — every published MX record (priority preserved), probed on TCP/25,
  587 and 465 independently. 25/587 speak SMTP: banner, EHLO, STARTTLS
  detection, in-place TLS upgrade; 465 is implicit TLS from the first byte.
  `STARTTLS unavailable` is reported distinctly and is never a PQ verdict.
  Domains without MX records are not probed
- `SUMMARY` — one phrase for web, one rollup for mail. Mail delivery rides
  on TCP/25 alone (`PQ enabled` → `classical TLS only` → `TLS failed` →
  `no TLS` → `MX discovered; SMTP/25 unreachable from probe`); when 25 is
  unreachable the summary keeps the attribution instead of collapsing to
  `unreachable`

| verdict | description |
| --- | --- |
| `pq_at_edge` | PQ or hybrid key exchange with at least two independent edge/CDN/WAF indications. |
| `pq_likely_at_edge` | PQ or hybrid key exchange with one strong edge indication. |
| `pq_on_org_infra` | PQ or hybrid key exchange on infrastructure attributed to the organization itself. |
| `pq_on_third_party_infra` | PQ or hybrid key exchange on infrastructure attributed to a third party. |
| `pq_unattributed` | PQ or hybrid key exchange; infrastructure could not be attributed. |
| `classical_at_edge` | No PQ key exchange, with at least two independent edge/CDN/WAF indications. |
| `classical_likely_at_edge` | No PQ key exchange, with one strong edge indication. |
| `classical_on_org_infra` | No PQ key exchange on infrastructure attributed to the organization itself. |
| `classical_on_third_party_infra` | No PQ key exchange on infrastructure attributed to a third party. |
| `classical_unattributed` | No PQ key exchange; infrastructure could not be attributed. |
| `tls_unavailable` | The HTTPS endpoint was unreachable; PQ status unknown. |

## Installation

From crates.io (requires Rust):

```console
$ cargo install pq-pulse
```

Or grab a prebuilt binary from [GitHub Releases](https://github.com/post-q/pq-pulse/releases)
(`pq-pulse-v<version>-<target>.tar.gz` for Linux x86_64/aarch64 and macOS aarch64).

## Requirements

- `dig` on PATH (MX, A/AAAA, CNAME/PTR/TXT lookups are shell-outs; origin ASN
  via Team Cymru DNS)
- network access; one HTTPS request per domain for HTTP evidence, one SMTP
  dialogue per reachable mail port, RDAP lookups per endpoint; provider IP
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
