{ lib, ... }: {
  boot.initrd.systemd.enable = true;
  networking.firewall.allowedTCPPorts = [ 80 ];
  nix.enable = false;
  services.httpd = {
    enable = true;
  };
  system = {
    etc.overlay.enable = true;
    stateVersion = "25.05";
  };
  systemd.shutdownRamfs.enable = false;
  users = {
    mutableUsers = false;
    users.nixos = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
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
