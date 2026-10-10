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
      max_file_bytes = positiveSetting (100 * 1024 * 1024) "Maximum signed ZIP size.";
      max_total_bytes = positiveSetting (
        10 * 1024 * 1024 * 1024
      ) "Persistent reserved ZIP-byte quota, not tar bytes.";
      max_inflight = positiveSetting 2 "Maximum concurrent admitted uploads.";
      max_manifest_bytes = positiveSetting 4096 "Maximum decoded signed manifest size.";
      max_lifetime_secs = positiveSetting 3600 "Maximum manifest lifetime.";
      upload_timeout_ms = positiveSetting 120000 "Whole-body upload deadline.";
      roster_max_age_secs = positiveSetting 3600 "Maximum roster mtime age.";
      s3_timeout_ms = positiveSetting 30000 "S3 request deadline.";
    };
  };
  config = lib.mkIf cfg.enable {
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
  };
}
