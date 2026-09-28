{
  description = "JIT-Hater — behavioral memory threat detector for Linux (watch process memory activity, dump suspicious regions)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, flake-utils, crane }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;

        # Only Rust sources matter for source filtering (fast, cache-friendly
        # rebuilds); keep the config/ directory so the example yaml ships.
        src = craneLib.cleanCargoSource (craneLib.path ./.);
        commonArgs = {
          inherit src;
          strictDeps = true;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ ];
        };

        # Build *just* the cargo dependencies for caching.
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        jit-hater = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            pname = "jit-hater";
            meta = with pkgs.lib; {
              description = "Behavioral memory threat detector for Linux (watch, dump, analyze)";
              homepage = "https://github.com/JIT-Hater/jit-hater";
              license = licenses.asl20;
              platforms = platforms.linux;
              mainProgram = "jit-hater";
            };
          }
        );
      in
      {
        packages = {
          inherit jit-hater;
          default = jit-hater;
        };

        apps.default = flake-utils.lib.mkApp { drv = jit-hater; };

        devShells.default = craneLib.devShell {
          inherit cargoArtifacts;
          packages = with pkgs; [
            rust-analyzer
            clippy
            rustfmt
          ];
        };

        checks = {
          jit-hater-tests = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );
          jit-hater-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );
        };
      }
    );
}
