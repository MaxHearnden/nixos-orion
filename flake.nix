{
  inputs = {
    cardgames = {
      flake = false;
      url = "git+ssh://git@github.com/MaxHearnden/cardgen.js";
    };
    compsoc-website = {
      flake = false;
      url = "github:MaxHearnden/Compsoc-Website-cobalt";
    };
    cspc = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:MaxHearnden/cspc";
    };
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
    pkgs-unstable = nixpkgs-unstable.legacyPackages;
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
        specialArgs = { inherit inputs; };
        system = "aarch64-linux";
      };
    };
    packages = lib.genAttrs lib.systems.flakeExposed (system: {
      default = (lib.nixosSystem {
        modules = [
          ./configuration.nix
        ];
        specialArgs = {
          inherit inputs;
          pkgs-unstable = nixpkgs-unstable.legacyPackages;
        };
        inherit system;
      }).config.system.build.vm;
    });
  };
}
