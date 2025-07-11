{ lib, modulesPath, pkgs, ... }: {
  boot = {
    kernelPackages = pkgs.linuxPackages_latest;
    initrd.systemd.enable = true;
  };
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.2.1
    options trust-ad edns0
  '';
  imports = [ "${modulesPath}/profiles/perlless.nix" ];
  networking.firewall.allowedTCPPorts = [ 80 ];
  nix.enable = false;
  nixpkgs.config.contentAddressedByDefault = true;
  services = {
    nginx.enable = true;
    userborn.enable = true;
  };
  system = {
    etc.overlay = {
      enable = true;
      mutable = false;
    };
    stateVersion = "25.05";
  };
  systemd.shutdownRamfs.enable = false;
  users = {
    mutableUsers = false;
    users.nixos = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      packages = [
        pkgs.dig
      ];
      password = "nixos";
    };
  };
  virtualisation.vmVariant.virtualisation = {
    diskImage = null;
    fileSystems."/".options = [ "noatime" "nodev" "noexec" "nosuid" ];
    graphics = false;
    qemu = {
      consoles = [ "ttyAMA1,115200n8" "ttyAMA0,115200n8" ];
      networkingOptions = lib.mkForce [
        "-nic tap,ifname=web-vm,script=no,downscript=no"
      ];
      options = [
        "-serial stdio"
        "-serial mon:pty:/run/web-vm/mon"
      ];
    };
    writableStore = false;
  };
}
