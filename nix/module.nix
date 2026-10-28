{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.uketsuke;
  json = pkgs.formats.json { };
  settings = cfg.settings // {
    staging_dir = "/var/lib/uketsuke/staging";
    roster_path = cfg.rosterFile;
  };
  configFile = json.generate "uketsuke.json" settings;
  upstream = "http://127.0.0.1:${toString cfg.settings.port}";
  nginxHost =
    let
      host = builtins.match "https://([^/:]+)" cfg.settings.service;
    in
    if host == null then
      throw "services.uketsuke.nginx.enable needs settings.service to be https://<host> without port or path, got '${cfg.settings.service}'"
    else
      builtins.head host;
  # "x-upload-manifest: " + base64 manifest + CRLF, as Config.max_header_bytes
  # counts it; the e2e proxy test sends a max_manifest_bytes manifest through
  # nginx, so the two cannot drift apart unnoticed.
  manifestHeaderBytes = 19 + 4 * ((cfg.settings.max_manifest_bytes + 2) / 3) + 2;
  stringSetting =
    description:
    mkOption {
      type = types.str;
      inherit description;
    };
  positiveSetting =
    default: description:
    mkOption {
      type = types.ints.positive;
      inherit default description;
    };
  # The grammar Config.from_map! accepts, and a subset of nginx's time syntax,
  # so a value passes to nginx unchanged.
  duration = types.strMatching "[1-9][0-9]*(ms|s|m|h)";
  durationSetting =
    default: description:
    mkOption {
      type = duration;
      inherit default description;
    };
  durationMs =
    text:
    let
      parts = builtins.match "([1-9][0-9]*)(ms|s|m|h)" text;
      unitMs = {
        ms = 1;
        s = 1000;
        m = 60000;
        h = 3600000;
      };
    in
    lib.toInt (builtins.head parts) * unitMs.${builtins.elemAt parts 1};
in
{
  options.services.uketsuke = {
    enable = lib.mkEnableOption "the loopback-only signed report inbox";
    package = mkOption {
      type = types.package;
      default = import ./package.nix { inherit pkgs; };
    };
    environmentFile = mkOption {
      type = types.str;
      description = "Absolute runtime file with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY; optional AWS_SESSION_TOKEN. Do not put operational secrets in the Nix store.";
    };
    rosterFile = mkOption {
      type = types.str;
      description = "Absolute path to the externally refreshed readable roster JSON. Uketsuke does not fetch a roster.";
    };
    settings = {
      service = stringSetting "Public HTTPS origin used in signed manifests (loopback HTTP is allowed for development).";
      network = stringSetting "Signed network identity.";
      campaign = stringSetting "Signed campaign identity.";
      s3_bucket = stringSetting "Existing private S3 archive bucket.";
      s3_region = stringSetting "S3 signing region.";
      s3_endpoint = stringSetting "S3 API endpoint.";
      s3_prefix = stringSetting "Unique per-inbox archive prefix ending in '/', separate from Metsuke v1/.";
      port = positiveSetting 4000 "Loopback listener port.";
      metrics_port = mkOption {
        type = types.ints.between 1 65535;
        description = "Loopback Prometheus port serving GET /metrics. Never proxy it publicly; it must differ from port.";
      };
      max_file_bytes = positiveSetting (100 * 1024 * 1024) "Maximum signed ZIP size.";
      max_total_bytes = positiveSetting (
        10 * 1024 * 1024 * 1024
      ) "Persistent reserved ZIP-byte quota, not tar bytes.";
      max_inflight = positiveSetting 2 "Maximum concurrent admitted uploads.";
      max_manifest_bytes = positiveSetting 4096 "Maximum decoded signed manifest size.";
      campaign_lifetime = durationSetting "55m" "Manifest lifetime the published Campaign tells pools to sign; whole seconds, at least twice clock_skew.";
      clock_skew = durationSetting "5m" "How far ahead of this server a pool's clock may run; the server accepts expiries up to campaign_lifetime + clock_skew. Whole seconds.";
      upload_timeout = durationSetting "2m" "Whole-body upload deadline.";
      roster_max_age = durationSetting "1h" "Maximum roster mtime age.";
      s3_timeout = durationSetting "30s" "S3 request deadline.";
      progress_interval = durationSetting "15s" "How often the server sends 103 Early Hints while it writes the Bundle and publishes it, so ukc, which cancels after 60 s without a byte, keeps waiting. Must be under 60 s.";
    };
    nginx.enable = lib.mkEnableOption "an nginx virtual host for the host in `settings.service`, proxying it to the listener; TLS and rate limits are left to the deployment";
    nginx.responseTimeout = mkOption {
      type = duration;
      default = "${toString (3 * durationMs cfg.settings.s3_timeout + 60000)}ms";
      defaultText = lib.literalExpression "3 * settings.s3_timeout + 60s";
      description = "How long nginx waits for the response once the body is sent. The server then reserves quota (one s3_timeout deadline across ledger reads and conditional write retries), writes the Bundle and PUTs it (one more each); the 60 s on top covers writing a max_file_bytes Bundle to staging. Shorter, and a stored report reaches the pool as a 504.";
    };
  };
  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = lib.hasPrefix "/" cfg.environmentFile;
            message = "services.uketsuke.environmentFile must be absolute";
          }
          {
            assertion = lib.hasPrefix "/" cfg.rosterFile;
            message = "services.uketsuke.rosterFile must be absolute";
          }
          {
            assertion = cfg.settings.port <= 65535;
            message = "services.uketsuke.settings.port must be <= 65535";
          }
          {
            assertion = cfg.settings.metrics_port != cfg.settings.port;
            message = "services.uketsuke.settings.metrics_port must differ from port";
          }
        ];
        systemd.services.uketsuke = {
          description = "Uketsuke signed report inbox";
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          environment = {
            INBOX_CONFIG = "${configFile}";
            RELEASE_COOKIE = "uketsuke-local-nondistributed";
            RELEASE_DISTRIBUTION = "none";
            ERL_FLAGS = "+S 2:2";
          };
          serviceConfig = {
            ExecStart = "${lib.getExe cfg.package} start";
            EnvironmentFile = cfg.environmentFile;
            DynamicUser = true;
            StateDirectory = "uketsuke";
            StateDirectoryMode = "0700";
            WorkingDirectory = "/var/lib/uketsuke";
            Restart = "on-failure";
            UMask = "0077";
            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            PrivateDevices = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectControlGroups = true;
            RestrictSUIDSGID = true;
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
            CapabilityBoundingSet = "";
            LockPersonality = true;
            ReadWritePaths = [ "/var/lib/uketsuke" ];
          };
        };
      }
      (lib.mkIf cfg.nginx.enable {
        assertions = [
          {
            # nginx reads each request header line into one 8k
            # large_client_header_buffers buffer and refuses longer lines itself.
            assertion = manifestHeaderBytes <= 8192;
            message = "services.uketsuke.settings.max_manifest_bytes ${toString cfg.settings.max_manifest_bytes} makes an x-upload-manifest header of ${toString manifestHeaderBytes} bytes, over nginx's 8192-byte header line";
          }
        ];
        services.nginx = {
          enable = true;
          virtualHosts.${nginxHost}.locations = {
            "/" = {
              proxyPass = upstream;
              recommendedProxySettings = true;
              # Unbuffered so the server's admission check (roster key, quota,
              # in-flight slot) runs before the body is read, rather than after
              # nginx has spooled up to max_file_bytes to disk; nginx buffers
              # chunked bodies over HTTP/1.0 regardless. client_body_timeout is
              # per read; the server holds the whole-body deadline.
              # No body limit here: the server refuses a signed file_size over
              # max_file_bytes before reading the body, with the JSON error ukc
              # reports, and stops reading at the signed size; nginx's own 413
              # is an HTML page ukc cannot read.
              # early_hints passes the server's 103 heartbeats on to the client;
              # nginx forwards up to proxy_buffer_size of them per request, and
              # drops any whose headers it all hides. Each also resets
              # proxy_read_timeout. The server sends them only over HTTP/1.1.
              extraConfig = ''
                client_max_body_size 0;
                early_hints 1;
                proxy_http_version 1.1;
                proxy_request_buffering off;
                proxy_send_timeout ${cfg.settings.upload_timeout};
                proxy_read_timeout ${cfg.nginx.responseTimeout};
              '';
            };
            # Its own location so deployments can limit probes apart from uploads.
            "= /healthz" = {
              proxyPass = upstream;
              recommendedProxySettings = true;
            };
          };
        };
      })
    ]
  );
}
