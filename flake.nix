{
  description = "Logos QR signer: air-gapped wallets that sign over animated QR codes, behind the signer interface. Holds no secret.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # The camera, and the codes on screen. A dependency, so it loads with the signer.
    qr_scanner_module = {
      url = "github:logos-co/logos-qr-scanner-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      lib = nixpkgs.lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross target the builder understands, never a host.
      targets = systems ++ [ "x86_64-windows" ];

      # A QR wallet in software for the doctests: the crate's own emulator, staged beside the SDK
      # source its manifest names, built without the module.
      emulator = system:
        let
          pkgs = import nixpkgs { inherit system; };
          src = pkgs.runCommand "qr-device-emulator-src" { } ''
            mkdir -p $out
            cp -r ${./rust-lib} $out/rust-lib
            cp -r ${logos-module-builder.packages.${system}.rust-sdk-src} $out/logos-rust-sdk-src
          '';
        in
        pkgs.rustPlatform.buildRustPackage {
          pname = "qr-device-emulator";
          version = "0.1.0";
          inherit src;
          sourceRoot = "qr-device-emulator-src/rust-lib";
          cargoLock = {
            lockFile = ./rust-lib/Cargo.lock;
            allowBuiltinFetchGit = true;
          };
          buildNoDefaultFeatures = true;
          buildFeatures = [ "emulator" ];
          cargoBuildFlags = [ "--bin" "qr-device-emulator" "--bin" "qr-psbt-for" ];
          doCheck = false;
          meta.mainProgram = "qr-device-emulator";
        };
    in
    {
      packages = lib.genAttrs targets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system}
        // lib.optionalAttrs (builtins.elem system systems) { emulator = emulator system; });
    };
}
