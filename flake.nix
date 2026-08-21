{
  description = "EGF-dev: LLVM 16 + SVF + patched AFL++ research environment (devcontainer parity)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in
    {
      devShells = forAllSystems (pkgs: {
        default = import ./nix/shell.nix { inherit pkgs; };
      });

      # Deliberately no `apps.bootstrap`: it would have to exec a path relative
      # to wherever `nix run` was invoked, and it needs the devShell's env
      # anyway. Use `bootstrap-egf` from inside `nix develop`.

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
