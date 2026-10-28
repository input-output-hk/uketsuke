# Reference

[Quickstart](../README.md) · [Operation](#operate-the-service) ·
[Observability](#observability) · [Development](#develop-and-test) ·
[Protocol](#protocol-and-archive)

## Upload details

Campaign service, network, and campaign must match server configuration; the
expiry may be at most `campaign_lifetime` + `clock_skew` past the server's
clock. For a real network, use an identifier
tied unambiguously to its genesis. Only loopback HTTP is permitted by `ukc`;
remote origins must use HTTPS.

Signing reads the local report incrementally, hashes it with SHA-256 and signs
a manifest. It accepts both current and historical `Mininimal` BLS
TextEnvelope spellings and rejects cold keys and invalid scalars. The signing
key never leaves `ukc`.

### `ukc send`

`--campaign` takes a local file or an `https://host/path` URL (`http://` only
on loopback). A fetched campaign must name the URL's origin as its `service`,
so the host authenticated by TLS is the one the Manifest is signed for and the
upload goes to. TLS trusts the system CA bundle (`/etc/ssl/certs/` and the
usual distribution paths), or only the PEM bundle named by `SSL_CERT_FILE`
when that is set. Proxy variables are ignored: Zig's HTTP client would tunnel
HTTPS through a proxy without a TLS handshake with the service. Behind a
proxy, use `ukc sign` and curl. Redirects are never followed, for the
campaign or the upload. Each request must connect (DNS, TCP and TLS) within
30 s, and is then canceled after 60 s without bytes sent or received. While
it writes the Bundle and publishes it, the server sends `103 Early Hints` every
`progress_interval` (under 60 s); `ukc` counts each as progress and waits for
the final answer. Through a proxy that drops 1xx responses, a publish slower
than 60 s fails the upload; retry with `--id`. `curl` prints the 103s with
`-v` and ignores them otherwise.

Before uploading, `ukc send` checks that the report's size and mtime are
unchanged since hashing, then prints `submission <id>: uploading <n> bytes to
<service>` to stderr. It streams exactly the signed size from the same open
file, with that `Content-Length`. Changes during the upload are caught by the
server: a modified signed range is rejected (422) and never published, while
bytes appended past the signed size are not sent, so the signed report is
archived. A report that shrinks is refused locally.

`ukc send` exits 0 and prints the receipt JSON on stdout only for a 2xx answer
whose body is a receipt for this submission. Everything else exits 1 with the
reason on stderr: a 4xx rejection with the server's JSON error; a 5xx, 408 or
429 answer, a 2xx that is not this submission's receipt (a captive portal, for
example), or a timeout or connection failure during the upload, each with
`retry with --id <id>`.

### `ukc sign` and curl

`ukc sign` never touches the network and takes only a local `--campaign` file.
It writes a new private request directory without overwriting one:
`manifest.json` holds the exact signed bytes; `upload.curl` and `receipt.curl`
are curl config files with the destination URL, the report's absolute path,
the base64 manifest, public key and signature, never the signing key.

`curl -q -K request/upload.curl` sends the report with an exact `Content-Length`
and prints the receipt; save it. Keep `-q` first: it prevents local curl
configuration from overriding transport settings. `receipt.curl` fetches the
receipt without sending the report. The configs need curl 7.76.0 or newer:
older curl ignores `fail-with-body` with a warning and exits 0 on a rejection.
A 4xx/5xx answer makes curl exit 22 with the status on stderr and the server's
JSON error on stdout. Redirects are not followed, so a 3xx from a proxy in
front of the service exits 0 without printing a receipt. Both configs disable
curl's URL globbing, so `[]` and `{}` in report paths and IPv6 hosts stay
literal. curl does not re-hash the report; a report changed after signing is
rejected (422) and never published. Keep the report and request directory
until the receipt is saved.

### Retries and recovery

Retries with the same ID and immutable metadata return the original receipt;
conflicting content gets 409. Rerun `ukc send` with
`--id PREVIOUS_SUBMISSION_ID` and the unchanged report; it signs a fresh expiry
and returns the original receipt. To recover the receipt without resending the
report, sign again with the same report, key, pool and campaign, which rebuilds
the Manifest from the report's hash:

```console
ukc sign --key bls.skey --file report.zip --pool POOL_HEX --campaign campaign.json \
  --id PREVIOUS_SUBMISSION_ID --out fresh-request
curl -q -K fresh-request/receipt.curl
```

Receipt lookup
requires a currently accepted roster key, so an outage or key rotation can
prevent recovery with an old key.

## Release builds

`ukc` is a static Linux binary without a dynamic loader or shared libraries;
`ukc send` over HTTPS needs a CA bundle on the host (see `ukc send` above).
Release assets named `ukc-*` start at 1.1.0. `nix build .#ukc-release` cross-builds `ukc-<version>-x86_64-linux` and
`ukc-<version>-aarch64-linux` (musl, no dynamic loader) plus `SHA256SUMS`.
This builds artifacts; it does not publish them.

The server and `ukc` are versioned apart: the server version is in `mix.exs`,
the client version in `client/build.zig.zon`, and only the client's own code
bumps the latter. A release is a repo state and carries the client build from
its commit, so a server-only release republishes the same `ukc-<version>-*`
bytes under the asset names they already had; the checksums make that visible.

Verify downloaded assets on the signing host:

```console
sha256sum -c --ignore-missing SHA256SUMS
```

An operator can independently rebuild at the release commit with
`nix build .#ukc-release --rebuild` and compare the resulting binary
checksums. The NixOS VM smoke uses the x86-64 client. The aarch64 release
binary also passes the upload smoke suite under QEMU user emulation on an
x86-64 host with aarch64 binfmt support; native ARM hardware is not tested.

## Operate the service

### Upgrade from 1.1.x

Version 1.2.0 changes the JSON configuration keys and the corresponding
`services.uketsuke.settings` options. Migrate them before restarting:

| Previous setting | Replacement example |
| --- | --- |
| `upload_timeout_ms: 120000` | `upload_timeout: "2m"` |
| `roster_max_age_secs: 3600` | `roster_max_age: "1h"` |
| `s3_timeout_ms: 30000` | `s3_timeout: "30s"` |
| `max_lifetime_secs: 900` | `campaign_lifetime: "10m"` and `clock_skew: "5m"` |

Choose `campaign_lifetime` and `clock_skew` explicitly: their sum replaces
the previous maximum lifetime, and `campaign_lifetime` must be at least
twice `clock_skew`. Add `progress_interval: "15s"`, which must be under 60 s.
The NixOS module supplies defaults for these duration settings; direct JSON
configuration requires every key. Preserve deployment-specific timeout and
roster-age values when converting units.

Replace separately hosted campaign JSON and landing pages with proxy routes
to the application. When using the optional nginx integration, retain the
deployment's TLS, firewall and rate-limit configuration. Other proxies must
forward HTTP/1.1 informational responses so upload progress reaches `ukc`.
Upgrade the client to 1.2.0 to handle those progress responses.

Copy `config.example.json` to `config.local.json`, provide a trusted refreshed
Key Roster and set runtime AWS credentials before starting. All JSON fields are
required; `staging_dir` and `roster_path` resolve relative to the config file.
Credentials come from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`;
`AWS_SESSION_TOKEN` is optional for temporary credentials and must be nonempty
when supplied. No instance-metadata credential lookup is performed.

```nu
$env.INBOX_CONFIG = (pwd | path join config.local.json)
mix run --no-halt
```

Every key is required. Durations (`campaign_lifetime`, `clock_skew`,
`upload_timeout`, `roster_max_age`, `s3_timeout`, `progress_interval`) are
strings of a positive
integer and a unit, `ms`, `s`, `m` or `h`: `"30s"`, `"15m"`. Anything else,
a bare number included, is refused at startup.

The server publishes its Campaign from config. `GET /campaigns/<campaign>.json`
answers `{"service", "network", "campaign", "lifetime_secs"}`, the URL to
announce for `ukc send --campaign`. `lifetime_secs` is `campaign_lifetime`.
The server accepts expiries up to `campaign_lifetime` + `clock_skew` ahead, so
a pool's clock may run `clock_skew` fast. Both are whole seconds, and
`campaign_lifetime` must be at least twice `clock_skew`, so a pool whose clock
runs `clock_skew` slow still has `clock_skew` to start its upload. `GET /` is a
page with that Campaign, its SHA-256 and `ukc send` instructions for the
client build from the same commit; server and `ukc` versions move apart, and
the page names both. `campaign` may use only `A-Z a-z 0-9 . _ -`. Both routes
and `/healthz` also answer HEAD. Neither route touches S3 or the roster; both
are rendered once at startup.

The Key Roster format is
`{"epoch": N, "slot": N, "pools": {"POOL_HEX": ["BLS_PUBLIC_KEY_HEX"]}}`.
It must come from a trusted chain query, not from the person uploading data.
Uketsuke does not generate the roster.

The flake exports `packages.<system>.uketsuke`, `packages.<system>.ukc`,
`packages.<system>.ukc-release`,
`nixosModules.uketsuke`, and `checks.<system>.release` / `checks.<system>.ukc`
/ `checks.<system>.smoke`. Example module configuration; replace the destination,
network, campaign, bucket, region, and file paths for your service:

```nix
{
  imports = [ inputs.uketsuke.nixosModules.uketsuke ];
  services.uketsuke = {
    enable = true;
    package = inputs.uketsuke.packages.x86_64-linux.uketsuke;
    environmentFile = "/run/secrets/uketsuke-aws-env";
    rosterFile = "/var/lib/uketsuke-roster.json";
    settings = {
      service = "https://uketsuke.example.org";
      network = "example-network";
      campaign = "reports";
      s3_bucket = "example-uketsuke-reports";
      s3_region = "eu-central-1";
      s3_endpoint = "https://s3.eu-central-1.amazonaws.com";
      s3_prefix = "uketsuke/reports/";
      metrics_port = 4001;
    };
  };
}
```

The module runs under DynamicUser with private staging at
`/var/lib/uketsuke/staging`, loopback HTTP and systemd confinement. The roster
must be readable by that identity. Keep operational credentials out of the Nix
store.

Expose the listener through an HTTPS reverse proxy. `services.uketsuke.nginx.enable`
adds an nginx virtual host named after the host in `settings.service`, which
must then be `https://<host>` without port or path. It proxies everything to
the listener over HTTP/1.1 with request buffering off, the recommended proxy
headers, no `client_max_body_size` (the server refuses an oversized signed
`file_size` with a JSON error before reading the body; nginx's own 413 is
HTML), `proxy_send_timeout` set to `upload_timeout` and `proxy_read_timeout`
to `nginx.responseTimeout` (default three `s3_timeout` for quota reservation,
Bundle write and PUT, plus 60 s for staging), and a separate `= /healthz`
location for probe limits. It asserts
that `max_manifest_bytes` fits nginx's 8 KiB header line once base64-encoded.
TLS, rate limits and firewall rules stay with the deployment; add them on
`services.nginx.virtualHosts.<host>`. With another server, replicate those
settings.

Roster generation/refresh, bucket provisioning, and live AWS verification are
operator responsibilities; this repository does not provision them.

## Observability

`GET /healthz` on the public listener answers 200 with
`{"status":"ready","roster":{"epoch":N,"slot":N,"pools":N,"age_secs":N}}`
while the Key Roster is valid and within `roster_max_age`, and 503 with
`{"status":"unavailable","error":{"code":"roster_unavailable"}}` otherwise. It
reads only the local roster, never S3, so probes cannot drive Archive cost. It
reuses the last parse while the roster file's device, inode, mtime and size are
unchanged, so a probe costs one `stat`; authorization always reparses. Replace
the roster by rename, as an in-place rewrite that keeps size and mtime is
invisible to the probe until it changes.

`GET /metrics` is served only on `127.0.0.1:<metrics_port>`, a separate
listener; do not proxy it. `metrics_port` 0 binds a free port, and the startup
line `UKETSUKE_READY http://127.0.0.1:<port> metrics=<url>` names the bound
ports. The NixOS module requires a fixed port. Series:

| Series | Type | Labels |
| --- | --- | --- |
| `uketsuke_requests_total` | counter | `route` (upload, receipt, other), `outcome` (accepted, recovered, rejected), `code` (error code, rejected only; `internal_error` for a server fault, `client_disconnected` when the client dropped the connection, `not_found` for other routes) |
| `uketsuke_request_duration_seconds` | histogram | `route` (upload, receipt) |
| `uketsuke_accepted_bytes_total` | counter | signed ZIP bytes of newly accepted Submissions |
| `uketsuke_inflight`, `uketsuke_inflight_max` | gauge | admitted slots now; `max_inflight` |
| `uketsuke_quota_reserved_bytes` | gauge | reserved ZIP bytes, the largest total any ledger read or write saw |
| `uketsuke_quota_max_bytes` | gauge | `max_total_bytes` |
| `uketsuke_s3_requests_total` | counter | `op` (head, get, put), `status` (HTTP status; `error` without a usable response: transport failure, or a response body over its size bound; `timeout` when the deadline killed the request) |
| `uketsuke_s3_request_duration_seconds` | histogram | `op` |
| `uketsuke_roster_ok` | gauge | 1 when the roster is valid and fresh |
| `uketsuke_roster_mtime_seconds`, `uketsuke_roster_epoch`, `uketsuke_roster_pools` | gauge | read at scrape; absent while the roster is invalid |

Startup reads the quota ledger once in the background;
`uketsuke_quota_reserved_bytes` stays absent until a ledger read succeeds, and
a failed startup read is logged with `event` `quota_startup_read_failed`. Holds
are never reclaimed, so the gauge never decreases; restart the service after
resetting a ledger by hand. Once reserved bytes reach
`max_total_bytes` every new upload gets `storage_quota`. Alert on
`time() - uketsuke_roster_mtime_seconds` for roster age. No label carries a
Pool or Submission ID.

Logs are one JSON object per line
([logger_json](https://hexdocs.pm/logger_json/7.0.4/) Basic formatter):
`time`, `severity`, `message` and an empty `metadata`. Every finished upload or
receipt request writes one line whose `message` is an object:

```json
{"time":"2026-10-14T12:00:00.000Z","severity":"info","metadata":{},"message":{"event":"request","route":"upload","outcome":"rejected","code":"storage_quota","status":507,"pool_id":"<56 hex>","submission_id":"<32 hex>","file_size":1234,"duration_ms":41}}
```

Loki: `{systemd_unit="uketsuke.service"} | json | message_event="request"`.
`code` appears only on rejections and is the public error code from the
response. `status` is absent when the request process did not answer: the
upload deadline killed it (`upload_timeout`), the client disconnected
(`client_disconnected`) or a server fault crashed it (`internal_error`). `submission_id` is absent unless the path ID is valid;
`pool_id` and `file_size` are absent until the Manifest parses, and are the
Manifest's claims, authenticated only for `accepted` and `recovered`. Manifest
bytes, keys and signatures are never logged. Server-side failures behind a
generic public message (`storage_failed`, `roster_unavailable`,
`verifier_unavailable`) are logged as `{"event":"private_error","code":…,"message":…}`;
other messages are a JSON string in `message`.

## Develop and test

The Nix development shell supplies Elixir/OTP, Zig, blst, Node, curl, OpenSSL,
zip, tar, AWS CLI and the `floci-dev` launcher. Zigler uses `ZIG_EXECUTABLE_PATH`
and links `$BLST_DIR/lib/libblst.a`; both are set by the shell. Node and
`@noble/curves` serve only the smoke harness, which forges malformed and
foreign-domain requests; operators never need them.

```console
nix develop
mix local.hex --force
mix deps.get
mix compile --warnings-as-errors
npm ci --prefix client --ignore-scripts --no-audit --no-fund
mix test
zig build --build-file client/build.zig test
nix build .#uketsuke .#ukc
```

With `qemu-aarch64` on PATH, run the aarch64 client tests with
`zig build --build-file client/build.zig test -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe -fqemu --summary all`.
To exercise the aarch64 release binary with the upload smoke suite below,
set `UKC` to its path on a host with aarch64 binfmt support.

`mix test` covers Manifest validation, real BLS authorization, Bundle round
trips and malformed archives. S3 integration tests are
tagged `s3` and excluded unless explicitly included. `zig build test` covers
`ukc`: the cardano-cli golden key in both spellings, rejected cold keys and
out-of-range scalars, signature verification and domain separation, campaign,
origin and campaign URL validation, curl config escaping, and the `ukc send`
watchdog: connect versus stall phases, and cancelation of a fetch from a
server that never answers and of an upload to a peer that stops reading.

**Backend prerequisite:** the Archive needs atomic `If-None-Match: *` and
`If-Match` PUT semantics. Production uses AWS S3. Development and the NixOS
smoke use [Floci](https://github.com/floci-io/floci) 2.2.0 (MIT), whose native
server is taken from the image pinned by
[floci-nix](https://github.com/imxade/floci-nix) and runs without a container
runtime. Garage ignores those conditions and cannot back this service; see
[Garage known issues](https://garagehq.deuxfleurs.fr/documentation/reference-manual/known-issues/).
Floci is a test emulator, not a storage backend for deployment.

`nix run .#floci-dev -- /tmp/uketsuke-floci` starts Floci on
`127.0.0.1:4566` with persistent state and SigV4 verification. EC2/ECS
emulation is off and Floci's Docker host points at a nonexistent socket, so the
fixture never touches a host container daemon.
On first start it uses Floci's public `test`/`test` pair
only to create a registered IAM access key, creates the `uketsuke` bucket and
writes both to `env.json` (mode 0600) in the state directory. Each start checks
that key against the persisted bucket. It refuses an occupied port, never
contacts AWS and stops the emulator on exit.

```nu
open /tmp/uketsuke-floci/env.json | load-env
zig build --build-file client/build.zig
$env.UKC = (pwd | path join client/zig-out/bin/ukc)
mix test --include s3
node --test client/smoke.test.mjs
nix build .#checks.x86_64-linux.smoke
```

The smoke signs a real ZIP with `ukc sign` and sends it with curl, and uploads
it with `ukc send` against the real server (local campaign, `--id` recovery,
4xx rejections). Against stand-in hosts it checks fetched campaigns: refused
foreign origins and redirects, an HTTPS fetch and upload trusted only through
`SSL_CERT_FILE` (openssl makes a throwaway CA), and 5xx, captive-portal and
gzipped answers. It checks S3 Bundle bytes, rejection paths,
interrupted/stalled transfers, Receipt replay, and quota after restart with
empty staging. The NixOS smoke runs the packaged release and `ukc` without
runtime compilation, plus a
separate `services.uketsuke` instance for loopback confinement and restart
checks. It also restarts Floci itself and checks that the Bundle ETag, quota
ledger and registered key survive while a wrong secret is still rejected.
`INBOX_SERVER_COMMAND="/path/to/bin/uketsuke start"` selects the release launcher
in the smoke; otherwise it uses `mix run --no-halt`.

## Protocol and archive

`PUT /v1/uploads/<32-lowercase-hex-id>` receives the exact ZIP, not multipart
data; the server never extracts it. `X-Upload-Manifest` is standard padded
base64 of the exact signed UTF-8 JSON bytes. `X-Upload-Key` is a 96-byte G2 key
in lowercase hex; `X-Upload-Signature` is a 48-byte G1 signature in lowercase
hex. Verification never parses and reserializes signed bytes. The Manifest
must contain each protocol field exactly once.

BLS uses minimal-signature-size with the domain tag
`LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`, specific
to this upload protocol. The Manifest binds protocol, destination, network,
campaign, pool ID, submission ID, digest, ZIP size, display filename and expiry.
Neither a display filename nor a BLS key becomes a storage path.

Admission reserves an in-flight slot before expensive BLS verification and
authenticates the Key Roster association before reading the body. Bounded reads
hash into private temporary files; a killed or disconnected owner releases its
slot and removes staging. A failed removal is logged with `event`
`staging_cleanup_failed` and left for the next start, which clears staging; it never fails the
request or other uploads. The body deadline ends after the ZIP is verified;
S3 operations have their own configured timeout.

The Archive layout is:

```text
<s3_prefix>quota.json
<s3_prefix>submissions/<submission_id>.tar
  report.zip
  manifest.json
  attestation.json
  receipt.json
```

Each uncompressed USTAR Bundle retains the untouched ZIP, exact signed
Manifest, Receipt, and an attestation with the public signing key, signature and the
`roster_epoch`/`roster_slot` of the Key Roster snapshot that authorized the key.
The roster itself is not copied: registrations at that point are chain history
(db-sync, explorer). The USTAR entry limit is 8,589,934,591 bytes; Config
rejects a larger `max_file_bytes`. Use a unique prefix for each inbox; prefixes
must be safe relative paths ending in `/` and cannot start with the reserved
`v1/` prefix. Pool attribution is recorded inside the Bundle, not inferred from
an object name or a pool ticker.

S3 publication uses create-only PUT. A new accepted Submission returns 201
with `durability: "s3"`; retries and `GET /v1/receipts/<id>` authenticate a
currently registered key, validate the stored Bundle and return its original
Receipt with 200. Different immutable metadata gets 409. S3 failure never
earns a Receipt. There is no local completed-Archive index or durable server
queue; clearing staging does not lose accepted Submissions.

`quota.json` is a versioned, conditional-update ledger of immutable identities
and original Receipts. It charges signed ZIP bytes before attempting Bundle
publication. Concurrent updates use ETags; contention is bounded by
`s3_timeout`. A failed or uncertain publication retains its reservation:
absence on a later HEAD cannot prove an earlier timed-out PUT will not land.
Retry the same ID and immutable metadata to recover the held capacity. Holds
are not automatically reclaimed. Recovering an existing Bundle only reads the
ledger: a Bundle without its reservation, or a missing ledger, fails as
`storage_failed` rather than being charged anew. Quota excludes Evidence, tar
padding and S3 object versions; provision storage and staging volume limits
separately.

Run one server per staging directory and use atomic-condition-capable S3.
Do not modify Bundles or the ledger behind the server. The server's IAM
principal needs `s3:GetObject` (also used for HEAD) and `s3:PutObject` on
`<s3_prefix>*`, plus `s3:ListBucket` on the bucket limited to that prefix:
without ListBucket, S3 answers 403 instead of 404 for missing keys, and every
new Submission fails as `storage_failed`. SSE-KMS buckets also need
`kms:GenerateDataKey` and `kms:Decrypt` on the bucket key. There is no report
download endpoint; archive consumers access S3 directly.
Roster freshness measures local mtime, not chain freshness; replacing a file
with old chain data does not make its registrations current.

