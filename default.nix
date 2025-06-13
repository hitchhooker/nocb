{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, sqlite
, libX11
, libxcb
}:

rustPlatform.buildRustPackage rec {
 pname = "nocb";
 version = "0.2.0";

 src = fetchFromGitHub {
   owner = "hitchhooker";
   repo = "nocb";
   rev = "v${version}";
   hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
 };

 cargoHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

 nativeBuildInputs = [
   pkg-config
 ];

 buildInputs = [
   sqlite
   libX11
   libxcb
 ];

 meta = with lib; {
   description = "X11 clipboard manager with compression and blob storage";
   homepage = "https://github.com/hitchhooker/nocb";
   license = licenses.mit;
   maintainers = with maintainers; [ ];
   platforms = platforms.linux;
   mainProgram = "nocb";
 };
}
