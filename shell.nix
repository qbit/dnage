{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    shellHook = ''
      export PS1='\u@\h:\w$ '
      export NO_COLOR=1
    '';
    nativeBuildInputs = [
      pkgs.buildPackages.go
      pkgs.buildPackages.gosec
      pkgs.buildPackages.gnumake
    ];
}
