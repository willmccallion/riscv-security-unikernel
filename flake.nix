{
  description = "RISC-V security unikernel: toolchain, QEMU and fuzzing environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        stable = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        nightly = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
          toolchain.minimal.override {
            extensions = [ "miri" "rust-src" "llvm-tools" ];
          });

        # cargo-fuzz and miri need nightly; everything else builds on the
        # pinned stable toolchain. The Makefile calls `$(CARGO_NIGHTLY)`.
        cargoNightly = pkgs.writeShellScriptBin "cargo-nightly" ''
          export PATH=${nightly}/bin:$PATH
          exec ${nightly}/bin/cargo "$@"
        '';

        guiRuntimeLibs = with pkgs; [
          libGL
          libxkbcommon
          wayland
          libx11
          libxcursor
          libxi
          libxrandr
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            stable
            cargoNightly
            cargo-fuzz
            qemu
            gnumake
            openssl
            iproute2
            libcap
            tcpdump
            (python3.withPackages (ps: [ ps.matplotlib ]))
          ];

          CARGO_NIGHTLY = "cargo-nightly";
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath guiRuntimeLibs;
        };
      });
}
