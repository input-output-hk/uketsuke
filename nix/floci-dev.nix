{ pkgs, floci }:
let
  fixtureExports = pkgs.lib.concatStringsSep " " (
    pkgs.lib.mapAttrsToList (
      name: value: "${name}=${pkgs.lib.escapeShellArg value}"
    ) floci.fixtureEnvironment
  );
in
pkgs.writeShellApplication {
  name = "floci-dev";
  runtimeInputs = [
    floci
    pkgs.awscli2
    pkgs.coreutils
    pkgs.curl
    pkgs.jq
  ];
  text = ''
    umask 077
    state="''${1:-$PWD/.floci}"
    mkdir -p "$state/data"
    state=$(realpath "$state")
    # Bootstrap is not resumable: an interrupted first start leaves the IAM user
    # in data/ without env.json, and create-user would then fail.
    if [ ! -f "$state/env.json" ] && [ -n "$(ls -A "$state/data")" ]; then
      echo "Floci state $state has data but no env.json (interrupted bootstrap); remove $state and rerun" >&2
      exit 1
    fi
    endpoint=http://127.0.0.1:4566
    # Refuse an occupied endpoint: never bootstrap credentials into someone
    # else's emulator or service.
    if curl --max-time 1 --silent "$endpoint" >/dev/null; then
      echo "Floci development endpoint $endpoint is already occupied" >&2
      exit 1
    fi
    cd "$state"
    export ${fixtureExports}
    FLOCI_PORT=4566 FLOCI_STORAGE_PERSISTENT_PATH="$state/data" \
      floci -Dquarkus.http.host=127.0.0.1 > "$state/server.log" 2>&1 &
    server=$!
    cleanup() { kill "$server" 2>/dev/null || true; wait "$server" || true; }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if ! curl --retry 30 --retry-connrefused --retry-delay 1 --max-time 2 --fail --silent "$endpoint/_floci/health" >/dev/null; then
      cat "$state/server.log" >&2
      exit 1
    fi
    export AWS_EC2_METADATA_DISABLED=true AWS_DEFAULT_REGION=us-east-1
    if [ ! -f "$state/env.json" ]; then
      # Floci's public test/test pair only bootstraps a registered IAM key;
      # every check then signs with the generated key.
      key=$(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test sh -c '
        aws --endpoint-url "$1" iam create-user --user-name uketsuke >/dev/null &&
        aws --endpoint-url "$1" iam create-access-key --user-name uketsuke' - "$endpoint")
      jq -n --argjson key "$key" --arg endpoint "$endpoint" '{
        INBOX_S3_ENDPOINT: $endpoint,
        INBOX_S3_BUCKET: "uketsuke",
        INBOX_S3_REGION: "us-east-1",
        AWS_ACCESS_KEY_ID: $key.AccessKey.AccessKeyId,
        AWS_SECRET_ACCESS_KEY: $key.AccessKey.SecretAccessKey
      }' > "$state/env.json.tmp"
      AWS_ACCESS_KEY_ID=$(jq -r .AWS_ACCESS_KEY_ID "$state/env.json.tmp") \
      AWS_SECRET_ACCESS_KEY=$(jq -r .AWS_SECRET_ACCESS_KEY "$state/env.json.tmp") \
        aws --endpoint-url "$endpoint" s3api create-bucket --bucket uketsuke >/dev/null
      mv "$state/env.json.tmp" "$state/env.json"
    fi
    # Proves the stored key and bucket survived in the persisted state.
    AWS_ACCESS_KEY_ID=$(jq -r .AWS_ACCESS_KEY_ID "$state/env.json") \
    AWS_SECRET_ACCESS_KEY=$(jq -r .AWS_SECRET_ACCESS_KEY "$state/env.json") \
      aws --endpoint-url "$endpoint" s3api head-bucket --bucket uketsuke >/dev/null
    cat <<EOF
    Floci ready on $endpoint; persistent state: $state
    SigV4 verification is on; credentials are local to this state directory.
    In another terminal (Nushell):
      open $state/env.json | load-env
    Server config: s3_endpoint=$endpoint, s3_bucket=uketsuke,
    s3_region=us-east-1, s3_prefix=uketsuke/v1/dev/, s3_timeout_ms=30000.
    Stop with Ctrl-C. Objects and credentials remain in $state.
    EOF
    wait "$server"
  '';
}
