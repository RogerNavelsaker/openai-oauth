{
  description = "OpenAI OAuth OCI image, built with Nix and Bun";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = pkgs.lib;
      version = "2.1.0";
      bun = pkgs.bun;
      source = pkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: type:
          let base = builtins.baseNameOf path;
          in base != "node_modules" && base != "dist" && base != ".turbo" && base != "coverage";
      };
      bunDeps = pkgs.stdenvNoCC.mkDerivation {
        pname = "openai-oauth-bun-deps";
        inherit version;
        src = source;
        nativeBuildInputs = [ bun ];
        outputHashMode = "recursive";
        outputHash = "sha256-MmkjrtUUdX0B9i4+1SyEmZKIUkIO/CHF8DYVCQLkk2E=";
        buildPhase = ''
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"
          bun install --frozen-lockfile --no-save
        '';
        installPhase = ''
          mkdir -p "$out"
          cp -R node_modules "$out/"
          for link in "$out"/node_modules/* "$out"/node_modules/@*/*; do
            [ -L "$link" ] || continue
            target=$(readlink "$link")
            case "$target" in
              ../../packages/*) package="''${target#../../}" ;;
              ../../apps/*) package="''${target#../../}" ;;
              *) continue ;;
            esac
            rm "$link"
            mkdir -p "$(dirname "$link")"
            cp -R "$package" "$link"
          done
          rm -f "$out"/node_modules/demo "$out"/node_modules/openai-oauth
        '';
        dontFixup = true;
      };
      openaiOauthCli = pkgs.stdenvNoCC.mkDerivation {
        pname = "openai-oauth";
        inherit version;
        src = source;
        nativeBuildInputs = [ bun pkgs.makeWrapper ];
        dontBuild = true;
        installPhase = ''
          mkdir -p "$out/lib/openai-oauth" "$out/bin" "$out/share/licenses/openai-oauth"
          cp -R packages scripts package.json turbo.json tsconfig.base.json "$out/lib/openai-oauth/"
          cp -RL ${bunDeps}/node_modules/. "$out/lib/openai-oauth/node_modules/"
          cd "$out/lib/openai-oauth"
          mkdir -p .nix-bin
          for tool in turbo tsup tsc; do
            printf '#!${bun}/bin/bun\nimport("%s")\n' "$(readlink -f "${bunDeps}/node_modules/.bin/$tool" | sed "s#${bunDeps}/node_modules/##")" > ".nix-bin/$tool"
            chmod +x ".nix-bin/$tool"
          done
          chmod -R u+w node_modules/.bin
          for tool in tsc tsup; do
            rm -f "node_modules/.bin/$tool"
            ln -s "$PWD/.nix-bin/$tool" "node_modules/.bin/$tool"
          done
          export PATH="$PWD/.nix-bin:${bun}/bin:$PATH"
          export PATH="${pkgs.nodejs_24}/bin:$PATH"
          mkdir -p packages/local/node_modules/@openai-oauth packages/ai-sdk/node_modules/@openai-oauth packages/openai-oauth/node_modules/@openai-oauth
          for package in local ai-sdk openai-oauth; do
            mkdir -p "packages/$package/node_modules/.bin"
            for tool in tsc tsup; do
              ln -sf "$PWD/.nix-bin/$tool" "packages/$package/node_modules/.bin/$tool"
            done
          done
          ln -s ../../../core packages/local/node_modules/@openai-oauth/core
          ln -s ../../../core packages/ai-sdk/node_modules/@openai-oauth/core
          ln -s ../../../local packages/ai-sdk/node_modules/@openai-oauth/local
          ln -s ../../../core packages/openai-oauth/node_modules/@openai-oauth/core
          ln -s ../../../local packages/openai-oauth/node_modules/@openai-oauth/local
          ln -s ../../../ai-sdk packages/openai-oauth/node_modules/@openai-oauth/ai-sdk
          ${bun}/bin/bun "$out/lib/openai-oauth/node_modules/turbo/bin/turbo" run build --filter=openai-oauth
          makeWrapper ${bun}/bin/bun "$out/bin/openai-oauth" \
            --add-flags "run $out/lib/openai-oauth/packages/openai-oauth/src/cli.ts" \
            --prefix PATH : "${lib.makeBinPath [ bun ]}"
          cp packages/openai-oauth/LICENSE "$out/share/licenses/openai-oauth/LICENSE"
          cp packages/openai-oauth/NOTICE "$out/share/licenses/openai-oauth/NOTICE"
        '';
        meta = {
          description = "OpenAI-compatible proxy using local ChatGPT OAuth credentials";
          homepage = "https://github.com/RogerNavelsaker/openai-oauth";
          license = lib.licenses.asl20;
          platforms = lib.platforms.linux;
        };
      };
      openaiOauthEntrypoint = pkgs.writeTextFile {
        name = "openai-oauth-entrypoint";
        destination = "/bin/openai-oauth-entrypoint";
        executable = true;
        text = ''
          #!${pkgs.dash}/bin/dash
          set -eu
          exec ${openaiOauthCli}/bin/openai-oauth "$@"
        '';
      };
      openaiOauthImage = pkgs.dockerTools.buildLayeredImage {
        name = "openai-oauth";
        tag = "v${version}";
        created = "1970-01-01T00:00:01Z";
        contents = [ openaiOauthCli openaiOauthEntrypoint bun pkgs.cacert (pkgs.dockerTools.fakeNss.override {
          extraPasswdLines = [ "openai-oauth:x:10001:10001:OpenAI OAuth:/data:/nonexistent" ];
          extraGroupLines = [ "openai-oauth:x:10001:" ];
        }) ];
        fakeRootCommands = ''
          mkdir -p ./data ./tmp ./usr/share/licenses
          chown 10001:10001 ./data
          chmod 0700 ./data
          chmod 1777 ./tmp
          ln -s ${openaiOauthCli}/share/licenses/openai-oauth ./usr/share/licenses/openai-oauth
        '';
        config = {
          User = "10001:10001";
          WorkingDir = "/data";
          Entrypoint = [ "${openaiOauthEntrypoint}/bin/openai-oauth-entrypoint" ];
          Cmd = [ "--device-auth" "--host" "0.0.0.0" "--port" "10531" ];
          Env = [ "HOME=/data" "CODEX_HOME=/data" "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          Volumes = { "/data" = { }; };
          StopSignal = "SIGTERM";
          Labels = {
            "org.opencontainers.image.source" = "https://github.com/RogerNavelsaker/openai-oauth";
            "org.opencontainers.image.version" = version;
            "org.opencontainers.image.licenses" = "Apache-2.0";
          };
        };
      };
    in {
      packages.${system} = {
        default = openaiOauthImage;
        inherit bunDeps;
        openai-oauth-cli = openaiOauthCli;
        openai-oauth-image = openaiOauthImage;
      };
      checks.${system} = { inherit bunDeps; openai-oauth-cli = openaiOauthCli; openai-oauth-image = openaiOauthImage; };
    };
}
