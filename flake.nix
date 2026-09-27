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
    )
    // {
      nixosModules.default =
        { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.jit-hater;
          # Render the NixOS options into a jit-hater YAML config.
          settingsFormat = pkgs.formats.yaml { };
          configFile = settingsFormat.generate "jit-hater.yaml" cfg.settings;
        in
        {
          options.services.jit-hater = {
            enable = mkEnableOption "JIT-Hater, the behavioral memory threat detector";

            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.system}.default;
              defaultText = literalExpression "jit-hater.packages.\${pkgs.system}.default";
              description = "The jit-hater package to use.";
            };

            settings = mkOption {
              type = types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  dump.directory = mkOption {
                    type = types.str;
                    default = "/dev/shm/jit-hater";
                    description = ''
                      Directory where suspicious memory pages are dumped.
                      Must live on a tmpfs: dumps may contain secrets held by
                      legitimate processes (browsers, keyrings...).
                    '';
                  };
                  dump.granularity = mkOption {
                    type = types.enum [
                      "page"
                      "vma"
                    ];
                    default = "page";
                    description = "Dump the 4KiB page or the whole VMA (capped).";
                  };
                  monitor.fluctuation_threshold = mkOption {
                    type = types.int;
                    default = 5;
                    description =
                      "Executable-state transitions on one page before a fluctuation dump.";
                  };
                  monitor.poll_interval_secs = mkOption {
                    type = types.int;
                    default = 5;
                    description = "/proc polling interval (fallback mode).";
                  };
                  scanner.interval_secs = mkOption {
                    type = types.int;
                    default = 300;
                    description = "Structural /proc scan period in service mode.";
                  };
                  rules.jit_allowlist = mkOption {
                    type = types.listOf types.str;
                    default = [ ];
                    description = "Process names tolerated by the fluctuation rule.";
                  };
                  log.format = mkOption {
                    type = types.enum [
                      "json"
                      "human"
                    ];
                    default = "json";
                  };
                  log.filter = mkOption {
                    type = types.str;
                    default = "info";
                  };
                };
              };
              default = { };
              description = "JIT-Hater configuration (see config/jit-hater.example.yaml).";
            };

            extraArgs = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "Extra CLI arguments passed to `jit-hater monitor`.";
            };
          };

          config = mkIf cfg.enable {
            systemd.tmpfiles.settings."10-jit-hater"."/dev/shm/jit-hater".d =
              lib.mkIf (cfg.settings.dump.directory == "/dev/shm/jit-hater")
                {
                  user = "root";
                  group = "root";
                  mode = "0700";
                };

            systemd.services.jit-hater = {
              description = "JIT-Hater — behavioral memory threat detector";
              after = [ "local-fs.target" ];
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart =
                  "${cfg.package}/bin/jit-hater monitor --config ${configFile} ${
                    lib.escapeShellArgs cfg.extraArgs
                  }";
                Restart = "on-failure";
                RestartSec = "5s";

                # Root agent with the minimum needed: read anything
                # (dumps/procfs), trace processes, eBPF.
                NoNewPrivileges = true;
                CapabilityBoundingSet = [
                  "CAP_DAC_READ_SEARCH"
                  "CAP_SYS_PTRACE"
                  "CAP_BPF"
                  "CAP_PERFMON"
                ];
                AmbientCapabilities = [
                  "CAP_DAC_READ_SEARCH"
                  "CAP_SYS_PTRACE"
                  "CAP_BPF"
                  "CAP_PERFMON"
                ];
                ProtectSystem = "strict";
                ProtectHome = "read-only";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [
                  "AF_UNIX"
                  "AF_NETLINK"
                ];
                RestrictNamespaces = true;
                LockPersonality = true;
                RestrictRealtime = true;
                SystemCallArchitectures = "native";
                StateDirectory = "jit-hater";
              };
            };
          };
        };
    };
}
