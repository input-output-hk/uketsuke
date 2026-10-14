# Uketsuke

Uketsuke (受付, “reception desk”) collects BLS-signed ZIP reports from
registered pool keys and stores each report, signed metadata, and receipt in
an immutable S3 archive. Signing happens locally; private keys are never sent.

Uketsuke runs at <https://uketsuke-leios.play.dev.cardano.org> for the Leios
testnet `leios-164`. Sign only with the Leios key registered for your pool on
that testnet, never a cold key. From release 1.1.0, static `ukc` client
binaries are built for Linux x86-64 and aarch64; aarch64 execution is not
smoke-tested. Release 1.0.0 ships the older `uketsuke-sign`, which has no
`send` command.

## Upload a report

You need a ZIP report and a disposable BLS signing key. `POOL_HEX` is your
pool's 56-character lowercase hex ID. Do not use a cold key.

From an approved source checkout, with Nix flakes enabled:

```console
nix run .#ukc -- send --key /secure/path/bls.skey --file report.zip --pool POOL_HEX \
  --campaign https://uketsuke-leios.play.dev.cardano.org/campaigns/glue.json > receipt.json
```

`ukc send` reads the campaign (fetching it when given a URL), signs the report
locally and uploads it. It prints the receipt; save it. Take the campaign URL,
or a `campaign.json` file, from the service operator's announcement. For hosts
without Nix, obtain the matching static `ukc` binary (release 1.1.0 or later)
and `SHA256SUMS` from an operator-approved
[release](https://github.com/input-output-hk/uketsuke/releases). Verify it as
described in [Release builds](docs/reference.md#release-builds), then replace
`nix run .#ukc --` with the binary's path. If no release assets are available
to you, ask the operator or build from the approved source.

If the upload fails, rerun the same command with `--id SUBMISSION_ID` (printed
to stderr) and the unchanged report. To sign on a host without network access,
use `ukc sign` and upload with curl; see
[Upload details](docs/reference.md#upload-details), which also covers expiry,
key rotation, and error responses.

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
