{ pkgs ? import <nixpkgs> { } }:

let
  php = pkgs.php83.buildEnv {
    extensions = { enabled, all }: enabled ++ (with all; [ curl pdo_mysql posix zip ]);
  };
in
pkgs.mkShell {
  packages = with pkgs; [
    actionlint
    gh
    go
    jq
    php
    php83Packages.composer
    shellcheck
    unzip
    zip
  ];
}
