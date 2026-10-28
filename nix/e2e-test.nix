{
  pkgs,
  package,
  ukc,
  floci,
  module,
}:
let
  endpoint = "http://127.0.0.1:4566";
  region = "us-east-1";
  # Written at boot by bootstrap: credentials come from Floci's IAM, never the store.
  credentials = "/run/uketsuke-aws-env";
  aws = "${pkgs.awscli2}/bin/aws --endpoint-url ${endpoint} --region ${region}";
  bootstrap = pkgs.writeShellScriptBin "floci-bootstrap" ''
    set -eu
    umask 077
    export AWS_EC2_METADATA_DISABLED=true
    # Floci's public test/test pair only creates the registered key used by
    # everything else; it is never handed to Uketsuke.
    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test ${aws} iam create-user --user-name uketsuke >/dev/null
    key=$(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test ${aws} iam create-access-key --user-name uketsuke)
    ${pkgs.jq}/bin/jq -r '.AccessKey | "AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nAWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)"' \
      <<<"$key" > ${credentials}
    set -a; . ${credentials}; set +a
    ${aws} s3api create-bucket --bucket uketsuke >/dev/null
  '';
  authCheck = pkgs.writeShellScriptBin "floci-auth-check" ''
    set -eu
    export AWS_EC2_METADATA_DISABLED=true
    set -a; . ${credentials}; set +a
    ${aws} s3api head-bucket --bucket uketsuke >/dev/null
    if AWS_SECRET_ACCESS_KEY=wrong ${aws} s3api head-bucket --bucket uketsuke 2>/tmp/denied; then
      echo 'Floci accepted a wrong secret' >&2
      exit 1
    fi
    ${pkgs.gnugrep}/bin/grep -q 403 /tmp/denied
    echo 'registered key accepted; wrong secret rejected with 403'
  '';
  nodeModules = pkgs.importNpmLock.buildNodeModules {
    npmRoot = ../client;
    nodejs = pkgs.nodejs_24;
  };
  client = pkgs.runCommand "uketsuke-smoke-client" { } ''
    mkdir -p "$out/client" "$out/nix"
    cp ${../client/smoke.test.mjs} "$out/client/smoke.test.mjs"
    cp ${./module-smoke.mjs} "$out/nix/module-smoke.mjs"
    ln -s ${nodeModules}/node_modules "$out/client/node_modules"
    ln -s ${nodeModules}/node_modules "$out/nix/node_modules"
  '';
  smoke = pkgs.writeShellScriptBin "uketsuke-smoke" ''
    set -eu
    set -a; . ${credentials}; set +a
    export AWS_DEFAULT_REGION=${region}
    export AWS_EC2_METADATA_DISABLED=true
    export INBOX_S3_ENDPOINT=${endpoint}
    export INBOX_S3_BUCKET=uketsuke
    export INBOX_S3_REGION=${region}
    export INBOX_SERVER_COMMAND="${package}/bin/uketsuke start"
    export UKC=${pkgs.lib.getExe ukc}
    export RELEASE_DISTRIBUTION=none
    export RELEASE_COOKIE=uketsuke-test-nondistributed
    export ERL_FLAGS="+S 2:2"
    if [ "$#" -eq 0 ]; then
      exec ${pkgs.nodejs_24}/bin/node --test ${client}/client/smoke.test.mjs
    fi
    exec ${pkgs.nodejs_24}/bin/node ${client}/nix/module-smoke.mjs "$@"
  '';
  # Stands in for a slow publish: three 103s a second apart, then the answer.
  hintingUpstream = pkgs.writeShellScript "hinting-upstream" ''
    set -euo pipefail
    while IFS= read -r line && [ "$line" != $'\r' ]; do :; done
    for _ in 1 2 3; do
      printf 'HTTP/1.1 103 Early Hints\r\nx-upload-stage: publishing\r\n\r\n'
      ${pkgs.coreutils}/bin/sleep 1
    done
    printf 'HTTP/1.1 201 Created\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}'
  '';
in
pkgs.testers.runNixOSTest {
  name = "uketsuke-floci";
  nodes.inbox =
    { ... }:
    {
      imports = [ module ];
      virtualisation.memorySize = 3072;
      virtualisation.cores = 2;
      environment.systemPackages = [
        pkgs.awscli2
        pkgs.zip
        pkgs.gnutar
        pkgs.curl
        pkgs.openssl
        bootstrap
        authCheck
        smoke
      ];
      systemd.services.floci = {
        description = "Floci local AWS emulator (test fixture)";
        wantedBy = [ "multi-user.target" ];
        environment = floci.fixtureEnvironment // {
          FLOCI_PORT = "4566";
          FLOCI_STORAGE_PERSISTENT_PATH = "/var/lib/floci";
        };
        serviceConfig = {
          ExecStart = "${pkgs.lib.getExe floci} -Dquarkus.http.host=127.0.0.1";
          # The JVM-style exit code after a clean SIGTERM shutdown.
          SuccessExitStatus = 143;
          DynamicUser = true;
          StateDirectory = "floci";
          StateDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/floci";
        };
      };
      services.uketsuke = {
        enable = true;
        inherit package;
        environmentFile = credentials;
        rosterFile = "/var/lib/uketsuke-roster.json";
        settings = {
          service = "http://127.0.0.1:4000";
          network = "smoke-network";
          campaign = "module";
          s3_bucket = "uketsuke";
          s3_region = region;
          s3_endpoint = endpoint;
          s3_prefix = "uketsuke/v1/module/";
          metrics_port = 4001;
          max_file_bytes = 3000;
          max_total_bytes = 3000;
        };
      };
      systemd.services.uketsuke.wantedBy = pkgs.lib.mkForce [ ];
    };
  # No archive and no roster: it checks what nginx forwards and refuses itself;
  # uketsuke answers the page and Campaign from config alone.
  nodes.proxy =
    { ... }:
    {
      imports = [ module ];
      environment.systemPackages = [ pkgs.socat ];
      environment.etc."uketsuke-aws-env".text = ''
        AWS_ACCESS_KEY_ID=unused
        AWS_SECRET_ACCESS_KEY=unused
      '';
      services.uketsuke = {
        enable = true;
        inherit package;
        environmentFile = "/etc/uketsuke-aws-env";
        rosterFile = "/var/lib/uketsuke-roster.json";
        nginx.enable = true;
        settings = {
          service = "https://inbox.test";
          network = "proxy-network";
          campaign = "proxied";
          s3_bucket = "uketsuke";
          s3_region = region;
          s3_endpoint = "http://127.0.0.1:1";
          s3_prefix = "uketsuke/v1/proxied/";
          metrics_port = 4001;
          max_file_bytes = 3000;
          # The largest the module's assertion admits: an 8189-byte header line.
          max_manifest_bytes = 6126;
        };
      };
    };
  testScript = ''
    import base64
    import json
    import time
    from datetime import datetime, timedelta
    start_all()
    inbox.wait_for_unit("floci.service")
    inbox.wait_for_open_port(4566, addr="127.0.0.1")
    with subtest("Floci listens on loopback only and verifies SigV4"):
        listeners = [l for l in inbox.succeed("ss -ltnpH").splitlines() if '"floci"' in l]
        assert listeners, "no Floci listener found"
        loopback = ("127.0.0.1:", "[::ffff:127.0.0.1]:")
        assert all(l.split()[3].startswith(loopback) for l in listeners), listeners
        inbox.fail("curl --connect-timeout 2 http://$(hostname -I | cut -d' ' -f1):4566/_floci/health")
        inbox.succeed("floci-bootstrap")
        print(inbox.succeed("floci-auth-check"))
    with subtest("module confinement, loopback and immutable archive"):
        print(inbox.succeed("uketsuke-smoke prepare"))
        inbox.succeed("systemctl start uketsuke")
        inbox.wait_for_unit("uketsuke.service")
        inbox.wait_for_open_port(4000, addr="127.0.0.1")
        inbox.succeed("ss -ltn 'sport = :4000' | ${pkgs.gnugrep}/bin/grep 127.0.0.1:4000")
        inbox.fail("curl --connect-timeout 2 http://$(hostname -I | cut -d' ' -f1):4000/v1/uploads/10101010101010101010101010101010")
        assert inbox.succeed("systemctl show uketsuke -p DynamicUser --value").strip() == "yes"
        assert inbox.succeed("systemctl show uketsuke -p ProtectSystem --value").strip() == "strict"
        print(inbox.succeed("uketsuke-smoke upload"))
    with subtest("module observability: healthz, loopback metrics and request log"):
        inbox.wait_for_open_port(4001, addr="127.0.0.1")
        inbox.succeed("ss -ltn 'sport = :4001' | ${pkgs.gnugrep}/bin/grep 127.0.0.1:4001")
        inbox.fail("curl --connect-timeout 2 http://$(hostname -I | cut -d' ' -f1):4001/metrics")
        inbox.fail("curl -sf http://127.0.0.1:4000/metrics")
        inbox.succeed("curl -sf http://127.0.0.1:4000/healthz | ${pkgs.gnugrep}/bin/grep -F '\"status\":\"ready\"'")
        metrics = inbox.succeed("curl -sf http://127.0.0.1:4001/metrics")
        for series in ['uketsuke_requests_total{route="upload",outcome="accepted"} 1',
                       "uketsuke_roster_ok 1", "uketsuke_inflight 0", "uketsuke_quota_max_bytes 3000"]:
            assert series in metrics, series
        reports = [json.loads(l) for l in inbox.succeed("journalctl -u uketsuke -o cat").splitlines() if l.startswith("{")]
        requests = [r["message"] for r in reports if isinstance(r["message"], dict) and r["message"].get("event") == "request"]
        accepted = [m for m in requests if m["outcome"] == "accepted"]
        assert len(accepted) == 1, reports
        assert {k: v for k, v in accepted[0].items() if k != "duration_ms"} == {
            "event": "request", "route": "upload", "outcome": "accepted", "status": 201,
            "pool_id": "ab" * 28, "submission_id": "10" * 16, "file_size": accepted[0]["file_size"],
        }, accepted[0]
        assert isinstance(accepted[0]["duration_ms"], int)
    with subtest("module restart keeps the archive and quota"):
        inbox.succeed("systemctl stop uketsuke; rm -rf /var/lib/uketsuke/staging; systemctl start uketsuke")
        inbox.wait_for_open_port(4000, addr="127.0.0.1")
        # The startup ledger read fills the gauge before any request touches the ledger.
        inbox.wait_until_succeeds("curl -sf http://127.0.0.1:4001/metrics | ${pkgs.gnugrep}/bin/grep -E '^uketsuke_quota_reserved_bytes [1-9][0-9]*$'", timeout=30)
        print(inbox.succeed("uketsuke-smoke restart"))
        print(inbox.succeed("uketsuke-smoke quota"))
        inbox.succeed("test -z \"$(ls -A /var/lib/uketsuke/staging)\"")
    with subtest("real release, signed client ZIPs, archive and persistent quota"):
        print(inbox.succeed("uketsuke-smoke", timeout=timedelta(seconds=180)))
    with subtest("Floci restart keeps Bundle, quota ledger and IAM key"):
        inbox.succeed("systemctl restart floci")
        inbox.wait_for_open_port(4566, addr="127.0.0.1")
        print(inbox.succeed("floci-auth-check"))
        print(inbox.succeed("uketsuke-smoke restart"))
        print(inbox.succeed("uketsuke-smoke quota"))
    with subtest("nginx vhost proxies the campaign page and the API"):
        proxy.wait_for_unit("nginx.service")
        proxy.wait_for_open_port(4000, addr="127.0.0.1")
        curl = "curl -s -H 'Host: inbox.test' http://127.0.0.1"
        campaign = json.loads(proxy.succeed(f"{curl}/campaigns/proxied.json"))
        assert campaign == {"service": "https://inbox.test", "network": "proxy-network",
                            "campaign": "proxied", "lifetime_secs": 3300}, campaign
        page = proxy.succeed(f"{curl}/")
        sha = proxy.succeed(f"{curl}/campaigns/proxied.json | sha256sum").split()[0]
        for text in ["https://inbox.test/campaigns/proxied.json", f"SHA-256 <code>{sha}</code>", "<code>proxy-network</code>"]:
            assert text in page, text
        assert "no-cache" in proxy.succeed(f"{curl}/ -o /dev/null -D -")
        health = proxy.succeed(f"{curl}/healthz -w '%{{http_code}}'")
        assert health.endswith("503") and "roster_unavailable" in health, health
        unrouted = proxy.succeed(f"{curl}/v1/nothing -w '%{{http_code}}'")
        assert unrouted.endswith("404") and '"not_found"' in unrouted, unrouted
        assert proxy.succeed(f"{curl}/ -I -o /dev/null -w '%{{http_code}}'") == "200"
        # A manifest padded to max_manifest_bytes reaches the server through
        # nginx's header limit, and an oversized report gets the server's JSON
        # refusal, which ukc reads, not nginx's HTML 413.
        manifest = json.dumps({
            "protocol": "leios-artifact-upload/v1", "service": "https://inbox.test",
            "network": "proxy-network", "campaign": "proxied", "pool_id": "ab" * 28,
            "submission_id": "10" * 16, "file_hash": "00" * 32, "file_size": 3001,
            "filename": "report.zip", "expires_at": int(time.time()) + 600,
        })
        manifest = base64.b64encode(manifest.ljust(6126).encode()).decode()
        proxy.succeed("head -c 3001 /dev/zero > /tmp/big")
        big = proxy.succeed(f"{curl}/v1/uploads/{'10' * 16} -H 'x-upload-manifest: {manifest}' -T /tmp/big -w '%{{http_code}}'")
        assert big.endswith("413") and '"file_too_large"' in big, big
    with subtest("nginx passes the server's 103 heartbeats to the client"):
        proxy.succeed("systemctl stop uketsuke")
        proxy.succeed("systemd-run --unit hinting socat TCP-LISTEN:4000,bind=127.0.0.1,reuseaddr,fork EXEC:${hintingUpstream}")
        proxy.wait_for_open_port(4000, addr="127.0.0.1")
        hinted = proxy.succeed(f"{curl}/v1/receipts/{'10' * 16} -v --trace-time -w '\\n%{{time_total}}' 2>&1")
        assert hinted.count("< HTTP/1.1 103 Early Hints") == 3, hinted
        assert "< HTTP/1.1 201 Created" in hinted, hinted
        elapsed = float(hinted.splitlines()[-1])
        assert elapsed >= 3, hinted
        response_times = [datetime.strptime(line.split()[0], "%H:%M:%S.%f")
                          for line in hinted.splitlines() if "< HTTP/1.1 " in line]
        assert len(response_times) == 4, hinted
        gaps = [(later - earlier).total_seconds() % 86400
                for earlier, later in zip(response_times, response_times[1:])]
        assert all(gap >= 0.9 for gap in gaps), hinted
        print(f"nginx forwarded three 103 responses and the final 201 in {elapsed:.3f} s; gaps: {gaps}")
    print("UKETSUKE_FLOCI_SMOKE_PASSED")
  '';
}
