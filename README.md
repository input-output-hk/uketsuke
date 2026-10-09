# Uketsuke

Uketsuke (受付, “reception desk”) is an inbox for one-off data collections.
This prototype accepts BLS-signed ZIP uploads, independently of metsuke's
telemetry and reward policies. The Elixir/Plug/Bandit server uses a Zig NIF,
built by Zigler, that links `blst` for verification and makes the Linux
syscalls for atomic publication and filesystem syncs.

### Client ergonomics

Signing and transport are both Node; no curl or native client binary is needed.
Signing requires local code: the checked
[cardano-cli node command surface](https://github.com/IntersectMBO/cardano-cli/blob/b788cd365e3dd6246d9099018f093ba351779f9c/cardano-cli/test/cardano-cli-golden/files/golden/help/dijkstra_node.cli)
generates BLS keys but exposes no arbitrary-message signer. This prototype
ships an inspectable JavaScript signer, `client/sign.mjs`, using the
`@noble/curves` version pinned in `client/package.json`, and an uploader,
`client/upload.mjs`, that uses only Node's standard library. Both require the
Node version named in that file's `engines` field; this does **not** achieve
zero additional client tooling. No key enters the server, the uploader or a
browser. Use disposable keys while evaluating this prototype.

Run from this directory, after inspecting the signer and dependencies:

```console
npm ci --prefix client --ignore-scripts --no-audit --no-fund
node client/sign.mjs --key /secure/path/bls.skey --file report.zip --pool POOL_HEX --campaign campaign.example.json --out request
node client/upload.mjs request
node client/upload.mjs --receipt request
```

Replace `POOL_HEX` with the pool's 56-character lowercase hex ID. The service
operator distributes one campaign JSON and destination to the Discord channel,
not individual upload links. Its service/network/campaign must match server
configuration; its lifetime must fit `max_lifetime_secs`. For a real network,
use an identifier tied unambiguously to its genesis, not just a friendly name.
Only loopback HTTP is permitted by the signer; remote origins must use HTTPS.

Signing reads the local report incrementally, hashes it with SHA-256 and signs
a manifest. It makes no network requests. It accepts both current and historical
`Mininimal` BLS TextEnvelope spellings, rejects cold keys and invalid scalars,
and writes a new private request directory without overwriting one:
`manifest.json` holds the exact signed bytes and `request.json` the signature,
public key and the report's absolute path, never the signing key.

The uploader re-checks the report's size and SHA-256 against the signed
manifest, sends it with an exact `Content-Length`, prints the receipt and saves
it as `request/receipt.json`. `--receipt` fetches the receipt without sending
the report. Any non-2xx answer exits 1 with the server's status and JSON error.
Keep the report and request directory until the receipt is saved.

Retries with the same ID and immutable metadata return the original receipt;
conflicting content gets 409. After expiry, rerun the signing command with
`--id PREVIOUS_SUBMISSION_ID --out fresh-request` and unchanged file/metadata,
then run `node client/upload.mjs --receipt fresh-request`. Receipt lookup
requires a currently accepted roster key, so an outage or key rotation can
prevent recovery with an old key.

### Run the server and exercise the full path

Prerequisites: Linux, Zig, blst, Elixir/OTP, Node, npm; the smoke also uses zip.
`flake.nix` provides them as the default dev shell (`nix develop`, or direnv).
`mix compile` builds the NIF with the Zig named by `ZIG_EXECUTABLE_PATH` and
statically links `$BLST_DIR/lib/libblst.a`; the dev shell sets both:

```console
# From this prototype directory
nix develop --command nu
mix local.hex --force
mix deps.get
mix compile
npm ci --prefix client --ignore-scripts --no-audit --no-fund
```

The following commands are Nushell. `mix test` checks the NIF directly:
blst against signatures from `@noble/curves`, classification of keys and
signatures outside the prime-order subgroups, no-replace publication, refusal of
symlinks, nested directories and FIFOs, and a sync failure after the rename. The
Node smoke creates public test-key fixtures, a real ZIP and an ephemeral server;
it exercises actual uploads through `client/upload.mjs`, archive bytes,
cryptographic rejection, interrupted transfers, quotas and restart recovery. It
removes its temporary data and stops the server:

```nu
mix test
node --test client/sign.test.mjs client/smoke.test.mjs
```

For a persistent local experiment, copy `config.example.json` to
`config.local.json`, supply `roster.json`, then run:

```nu
$env.INBOX_CONFIG = (pwd | path join config.local.json)
mix run --no-halt
```

All config fields are required; paths resolve relative to the config file.
The example's limits are trial settings, not measurements of representative
glue reports. The roster uses metsuke’s existing roster format:
`{"epoch": N, "slot": N, "pools": {"POOL_HEX": ["BLS_PUBLIC_KEY_HEX"]}}`.
It must come from a trusted chain query, not from the uploader. No reward
membership is consulted. This experiment has no non-BLS admission path.

### Protocol and storage boundary

The endpoint is `PUT /v1/uploads/<32-lowercase-hex-id>`. The body is the exact
ZIP, not multipart data; the server never extracts it. `X-Upload-Manifest` is
standard padded base64 of the **exact signed UTF-8 JSON bytes**;
`X-Upload-Key` is a 96-byte G2 key in lowercase hex and
`X-Upload-Signature` is a 48-byte G1 signature in lowercase hex. Verifiers
must not parse and reserialize JSON before verifying. The signer controls its
encoding; the server checks the manifest's exact required field set.

BLS uses minimal-signature-size with the domain tag
`LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`,
distinct from telemetry and consensus. The signed manifest binds protocol,
service, network, campaign, pool ID, submission ID, SHA-256 digest, byte count,
display filename and Unix expiry. A filename is never a storage path.

Admission verifies the roster association and signature before reading the
body. Bounded reads hash directly into private staging files. Publication
fsyncs the ZIP and evidence, atomically renames without replacement, and syncs
the directories before returning 201 and a `local-fsync` receipt. The store
process performs the rename, so cleanup after a killed upload process cannot
overlap a rename still running in the NIF. A retry or
`GET /v1/receipts/<id>` uses the same authentication headers and reconfirms
durability before returning 200. Rejections close the connection instead of
draining the supplied body. Oversized headers can be rejected by Bandit with
431 before application-level JSON errors. A stalled body can end with a closed
connection rather than a JSON timeout response.

The archive is `<storage_dir>/archive/<id>/`, containing `report.zip`,
`manifest.json`, `attestation.json`, the accepted `roster.json` and
`receipt.json`. Developer retrieval is through these local files, not a public
download API. Every startup syncs the storage directories' entries, removes
owned incomplete staging entries and reconstructs quota accounting from
completed archives. Run only one instance per storage
directory; do not modify an archive behind a running server.

This is an ergonomics experiment, not a public deployment configuration. It
binds only 127.0.0.1; remote use requires an HTTPS reverse proxy with aligned
body/header/time limits and streaming request handling. The configured total
quota counts ZIP bytes, not evidence/filesystem overhead; use a bounded volume
as well. Filesystem sync stalls during publication are not bounded by the
upload-body deadline. No S3 replication or power-loss fault injection
was exercised. Roster expiry measures local file mtime, not chain freshness;
replacing it with old chain data does not prove current registration. Unlike
metsuke's last-known-good behavior, this prototype refuses stale roster files.

