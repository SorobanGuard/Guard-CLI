{
  description = "Soroban Guard CLI — static analysis for Soroban smart contracts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        soroban-guard = pkgs.rustPlatform.buildRustPackage {
          pname = "soroban-guard-cli";
          version = "0.1.0";

          src = self;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          cargoBuildFlags = [ "-p" "soroban-guard-cli" ];
          cargoTestFlags = [ "-p" "soroban-guard-cli" ];

          meta = with pkgs.lib; {
            description = "Static analysis engine for Soroban smart contracts";
            homepage = "https://github.com/SorobanGuard/Guard-CLI";
            license = with licenses; [ mit asl20 ];
            mainProgram = "soroban-guard";
            platforms = platforms.unix;
          };
        };
      in
      {
        packages.default = soroban-guard;
        packages.soroban-guard = soroban-guard;

        apps.default = {
          type = "app";
          program = "${soroban-guard}/bin/soroban-guard";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            cargo-deny
            cargo-audit
          ];
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
