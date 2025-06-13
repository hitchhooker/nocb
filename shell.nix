{ pkgs ? import <nixpkgs> {} }:

let
  rust-overlay = import (builtins.fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/master.tar.gz";
  });
  pkgs-with-overlay = import <nixpkgs> {
    overlays = [ rust-overlay ];
  };
  rust-nightly = pkgs-with-overlay.rust-bin.nightly.latest.default;
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    # Build tools - nightly Rust
    rust-nightly
    pkg-config
    
    # X11/XCB dependencies
    xorg.libxcb
    xorg.libX11
    
    # Optional: for development
    rust-analyzer
    clippy
    rustfmt
  ];
  
  # Set up pkg-config paths
  PKG_CONFIG_PATH = "${pkgs.xorg.libxcb}/lib/pkgconfig";
}
