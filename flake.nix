{
  inputs = {
    nixos-kexec = {
      url = "github:MaxHearnden/nixos-kexec";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, self, ... }@inputs:
  let inherit (nixpkgs) legacyPackages lib;
  in {
    nixosConfigurations = {
      orion = lib.nixosSystem {
        modules = [
          ./configuration.nix
        ];
        specialArgs = { inherit inputs; };
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
