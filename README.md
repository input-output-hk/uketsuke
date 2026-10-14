# Uketsuke

Uketsuke (受付, “reception desk”) collects BLS-signed ZIP reports from
registered pool keys and stores each report, signed metadata, and receipt in
an immutable S3 archive. Signing happens locally; private keys are never sent.

Uketsuke runs at <https://uketsuke-leios.play.dev.cardano.org> for the Leios
testnet `leios-164`. Sign only with the Leios key registered for your pool on
that testnet, never a cold key. Static signer releases exist for Linux x86-64
and aarch64; aarch64 execution is not smoke-tested.

## Upload a report

You need curl 7.76.0 or newer, a ZIP report, a disposable BLS signing key, and
`campaign.json` from the service operator's trusted announcement channel.
`POOL_HEX` is your pool's 56-character lowercase hex ID. Do not use the example
campaign unchanged for a deployed service, or use a cold key.

From an approved source checkout, with Nix flakes enabled:

```console
nix run .#uketsuke-sign -- --key /secure/path/bls.skey --file report.zip --pool POOL_HEX --campaign campaign.json --out request
curl -q -K request/upload.curl
```

For hosts without Nix, obtain the matching static binary and `SHA256SUMS` from
an operator-approved [release](https://github.com/input-output-hk/uketsuke/releases).
Verify it as described in [Release builds](docs/reference.md#release-builds),
then replace `nix run .#uketsuke-sign --` with the binary's path. If no release
assets are available to you, ask the operator or build from the approved source.

Save the returned receipt. Keep the report unchanged and retain the request
directory until then. Keep `-q` first: it prevents local curl configuration
from overriding transport settings. Remote destinations must use HTTPS.

[Upload details and receipt recovery](docs/reference.md#upload-details)
cover retries, expiry, key rotation, and error responses.

## Operate or develop

The service requires AWS S3, runtime AWS credentials, a trusted chain-derived
key roster, and an HTTPS reverse proxy. It provides a NixOS module; operators
are responsible for provisioning and verifying their deployment.

[Deployment](docs/reference.md#operate-the-service) ·
[Builds and tests](docs/reference.md#develop-and-test) ·
[Protocol and archive format](docs/reference.md#protocol-and-archive)

## License

Copyright 2026 Input Output Global, Inc.

[Apache License, Version 2.0](LICENSE) (`Apache-2.0`).
Dependencies retain their own licenses.
