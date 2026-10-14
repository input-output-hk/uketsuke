# Reference

[Quickstart](../README.md) · [Operation](#operate-the-service) ·
[Observability](#observability) · [Development](#develop-and-test) ·
[Protocol](#protocol-and-archive)

## Upload details

Campaign service, network, and campaign must match server configuration; the
lifetime must fit `max_lifetime_secs`. For a real network, use an identifier
tied unambiguously to its genesis. Only loopback HTTP is permitted by the
signer; remote origins must use HTTPS.

Signing reads the local report incrementally, hashes it with SHA-256 and signs
a manifest. It accepts both current and historical `Mininimal` BLS
TextEnvelope spellings, rejects cold keys and invalid scalars, and writes a new
private request directory without overwriting one: `manifest.json` holds the
exact signed bytes; `upload.curl` and `receipt.curl` are curl config files with
the destination URL, the report's absolute path, the base64 manifest, public
key and signature, never the signing key.

`curl -q -K request/upload.curl` sends the report with an exact `Content-Length`
and prints the receipt; save it. `receipt.curl` fetches the receipt without
sending the report. The configs need curl 7.76.0 or newer: older curl ignores
`fail-with-body` with a warning and exits 0 on a rejection. A 4xx/5xx answer
makes curl exit 22 with the status on stderr and the server's JSON error on
stdout. Redirects are not followed, so a 3xx from a proxy in front of the
service exits 0 without printing a receipt. Both configs disable curl's URL
globbing, so `[]` and `{}` in report paths and IPv6 hosts stay literal. curl
does not re-hash the report; a report changed after signing is rejected (422)
and never published. Keep the report and request directory until the receipt
is saved.

Retries with the same ID and immutable metadata return the original receipt;
conflicting content gets 409. After expiry, rerun the signing command with
`--id PREVIOUS_SUBMISSION_ID --out fresh-request` and unchanged file/metadata,
then run `curl -q -K fresh-request/receipt.curl`. Receipt lookup
requires a currently accepted roster key, so an outage or key rotation can
prevent recovery with an old key.

## Release builds

The signer is a static Linux binary without runtime dependencies.
`nix build .#uketsuke-sign-release` cross-builds
`uketsuke-sign-<version>-x86_64-linux` and
`uketsuke-sign-<version>-aarch64-linux` (musl, no dynamic loader) plus
`SHA256SUMS`. This builds artifacts; it does not publish them.

Verify downloaded assets on the signing host:

```console
sha256sum -c --ignore-missing SHA256SUMS
```

An operator can independently rebuild at the release commit with
`nix build .#uketsuke-sign-release --rebuild` and compare the resulting binary
checksums. The x86-64 smoke does not execute the aarch64 binary.

## Operate the service

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

The Key Roster format is
`{"epoch": N, "slot": N, "pools": {"POOL_HEX": ["BLS_PUBLIC_KEY_HEX"]}}`.
It must come from a trusted chain query, not from the person uploading data.
Uketsuke does not generate the roster.

The flake exports `packages.<system>.uketsuke`, `packages.<system>.uketsuke-sign`,
`packages.<system>.uketsuke-sign-release`,
`nixosModules.uketsuke`, and `checks.<system>.release` / `checks.<system>.sign`
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
store. Expose the listener through an HTTPS reverse proxy with aligned header,
body and time limits and request buffering disabled. Reverse-proxy configuration,
roster generation/refresh, bucket provisioning, and live AWS verification are
operator responsibilities; this repository does not provision them.

## Observability

`GET /healthz` on the public listener answers 200 with
`{"status":"ready","roster":{"epoch":N,"slot":N,"pools":N,"age_secs":N}}`
while the Key Roster is valid and within `roster_max_age_secs`, and 503 with
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

The Nix development shell supplies Elixir/OTP, Zig, blst, Node, curl, zip,
tar, AWS CLI and the `floci-dev` launcher. Zigler uses `ZIG_EXECUTABLE_PATH`
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
nix build .#uketsuke .#uketsuke-sign
```

`mix test` covers Manifest validation, real BLS authorization, Bundle round
trips and malformed archives. S3 integration tests are
tagged `s3` and excluded unless explicitly included. `zig build test` covers
the signer: the cardano-cli golden key in both spellings, rejected cold keys and
out-of-range scalars, signature verification and domain separation, campaign
and origin validation, and curl config escaping.

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
$env.UKETSUKE_SIGN = (pwd | path join client/zig-out/bin/uketsuke-sign)
mix test --include s3
node --test client/smoke.test.mjs
nix build .#checks.x86_64-linux.smoke
```

The smoke signs a real ZIP with `uketsuke-sign`, sends it with curl through the
server and checks S3 Bundle bytes, rejection paths, interrupted/stalled
transfers, Receipt replay, and quota after restart with empty staging. The NixOS
smoke runs the packaged release and signer without runtime compilation, plus a
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
`s3_timeout_ms`. A failed or uncertain publication retains its reservation:
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

