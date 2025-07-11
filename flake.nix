{
  inputs = {
    nixos-kexec = {
      flake = false;
      url = "github:MaxHearnden/nixos-kexec";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, nixpkgs-unstable, self, ... }@inputs:
  let
    inherit (nixpkgs) legacyPackages lib;
    libVersionInfoOverlay =
      import "${nixpkgs-unstable}/lib/flake-version-info.nix" nixpkgs-unstable;
    lib-unstable = nixpkgs-unstable.lib;
    pkgs-unstable =
      lib.genAttrs nixpkgs-unstable.lib.systems.flakeExposed (system:
        (import nixpkgs-unstable { inherit system; }).extend (
          final: prev: {
            lib = prev.lib.extend libVersionInfoOverlay;
          }));
  in {
    nixosConfigurations = {
      orion = lib.nixosSystem {
        modules = [
          ./configuration.nix
        ];
        specialArgs = { inherit inputs pkgs-unstable; };
        system = "aarch64-linux";
      };
      web-vm = lib.nixosSystem {
        modules = [
          ./vm.nix
        ];
        system = "aarch64-linux";
      };
    };
  };
}
