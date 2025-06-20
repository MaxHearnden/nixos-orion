{ lib, ... }: {
  networking.firewall.allowedTCPPorts = [ 80 ];
  services.httpd = {
    enable = true;
  };
  system.stateVersion = "25.05";
  users.users.nixos = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    password = "nixos";
  };
  virtualisation.vmVariant.virtualisation = {
    diskImage = null;
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
