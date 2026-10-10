# Floci's native server, taken from the image pinned by floci-nix so it runs
# without a container runtime. The image's entrypoint only drops privileges and
# fixes data-directory ownership; systemd and the dev launcher own both here.
{ pkgs, image }:
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
