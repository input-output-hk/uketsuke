# Floci's native server, taken from the pinned upstream image so it runs
# without a container runtime. The image's entrypoint only drops privileges and
# fixes data-directory ownership; systemd and the dev launcher own both here.
{ pkgs }:
let
  # Preserve the image pins from floci-nix revision
  # 159be03d4fb1d80172084e1df7d9ff13866f1334, including archive naming for its hashes.
  image = pkgs.dockerTools.pullImage {
    imageName = "floci/floci";
    imageDigest = "sha256:e97cd0c1dc2aa14e7697fb5ef5018404c4d6345169dbd276315f0bed2c7b0520";
    finalImageName = "floci-nix/aws";
    finalImageTag = "2.2.0-sha256-e97cd0c1dc2aa14e";
    os = "linux";
    arch =
      {
        x86_64-linux = "amd64";
        aarch64-linux = "arm64";
      }
      .${pkgs.stdenv.hostPlatform.system};
    hash =
      {
        x86_64-linux = "sha256-GnsGBp30/TMW7ykYE4CKW/CCUhmqaPfi1rydnSn4jRY=";
        aarch64-linux = "sha256-kaLZw6Ajk+dAiSurHudHaPNgD1vcckTzFy+iBZ7YQBQ=";
      }
      .${pkgs.stdenv.hostPlatform.system};
  };
in
pkgs.stdenv.mkDerivation {
  pname = "floci-server";
  version = image.imageTag;
  src = image;
  dontUnpack = true;
  nativeBuildInputs = [
    pkgs.autoPatchelfHook
    pkgs.jq
  ];
  buildInputs = [ pkgs.stdenv.cc.libc ];
  installPhase = ''
    runHook preInstall
    mkdir image root
    tar -xf "$src" -C image
    for layer in $(jq -r '.[0].Layers[]' image/manifest.json); do
      if tar -tf "image/$layer" | grep -qx app/application; then
        tar -xf "image/$layer" -C root app/application
      fi
    done
    install -Dm755 root/app/application "$out/bin/floci"
    runHook postInstall
  '';
  # Settings shared by the dev launcher and the NixOS smoke. Docker points at a
  # path that never exists: shutdown still probes EC2/ECS containers, and each
  # unreachable probe retries for ~15 s; mocking EC2 and skipping the ECS sweep
  # makes SIGTERM return immediately and keeps the fixture off any host daemon.
  passthru.fixtureEnvironment = {
    FLOCI_STORAGE_MODE = "persistent";
    FLOCI_AUTH_VALIDATE_SIGNATURES = "true";
    FLOCI_SERVICES_EC2_ENABLED = "false";
    FLOCI_SERVICES_EC2_MOCK = "true";
    FLOCI_SERVICES_ECS_ENABLED = "false";
    FLOCI_SERVICES_ECS_RECONCILE_CONTAINERS_ON_STARTUP = "false";
    FLOCI_DOCKER_DOCKER_HOST = "unix:///nonexistent/floci-fixture-has-no-docker.sock";
  };
  meta = {
    description = "Floci local AWS emulator server (native build)";
    homepage = "https://github.com/floci-io/floci";
    license = pkgs.lib.licenses.mit;
    mainProgram = "floci";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
