{
  inputs = {
    nixos-kexec = {
      url = "github:MaxHearnden/nixos-kexec";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { nixpkgs, self, ... }@inputs:
  let inherit (nixpkgs) legacyPackages lib;
  in {
    nixosConfigurations.orion = lib.nixosSystem {
      modules = [
        ./configuration.nix
      ];
      specialArgs = { inherit inputs; };
      system = "aarch64-linux";
    };
  };
}
