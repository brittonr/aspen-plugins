{
  description = "Aspen WASM plugins";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      
      # Nightly rust with WASM targets
      rust = pkgs.rust-bin.nightly.latest.default.override {
        extensions = [ "rust-src" "rustfmt" "clippy" ];
        targets = [ "wasm32-unknown-unknown" "wasm32-wasip1" ];
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [
          rust
          pkgs.cargo-nextest
        ];
        
        shellHook = ''
          echo "Aspen WASM Plugins Development Shell"
          echo "Rust: $(cargo --version)"
          echo "Targets: wasm32-unknown-unknown, wasm32-wasip1"
        '';
      };
    };
}
