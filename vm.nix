{ inputs, lib, modulesPath, pkgs, ... }:

let
  cardgames = pkgs.buildNpmPackage {
    pname = "cardgen";
    version = "0.1.0";
    patches = [
      ./wss.cardgames.zandoodle.me.uk.patch
    ];
    npmDepsHash = "sha256-MtgXmaEp3gqfS+lir7TN910WuRRldxit9OhyLrmzai4=";
    dontNpmBuild = true;
    src = inputs.cardgames;
    meta.mainProgram = "cardgen";
  };
in

{
  boot = {
    kernelPackages = pkgs.linuxPackages_latest;
    initrd.systemd.enable = true;
  };
  environment.etc = {
    "machine-id".text = "";
    "resolv.conf".text = ''
      nameserver 192.168.2.1
      options trust-ad edns0
    '';
  };
  imports = [ "${modulesPath}/profiles/perlless.nix" ];
  networking.firewall.allowedTCPPorts = [ 80 ];
  nix.enable = false;
  security = {
    doas = {
      enable = true;
      wheelNeedsPassword = false;
    };
    polkit.enable = true;
    sudo.enable = false;
  };
  services = {
    getty.autologinUser = "nixos";
    userborn.enable = true;
  };
  system = {
    etc.overlay = {
      enable = true;
      mutable = false;
    };
    stateVersion = "25.05";
  };
  systemd = {
    services.cardgames = lib.mkIf (builtins.pathExists "${inputs.cardgames}/cardgames") {
      confinement.enable = true;
      serviceConfig = {
        AmbientCapabilities = "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
        ExecStart = lib.getExe cardgames;
        Group = "cardgames";
        IPAddressAllow = "192.168.2.0/30";
        IPAddressDeny = "any";
        LockPersonality = true;
        NoNewPrivileges = true;
        PrivateMounts = true;
        PrivateUsers = lib.mkForce false;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictAddressFamilies = "AF_INET";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        UMask = "077";
        User = "cardgames";
      };
      wantedBy = [ "multi-user.target" ];
    };
    shutdownRamfs.enable = false;
  };
  users = {
    allowNoPasswordLogin = true;
    groups.cardgames = {};
    mutableUsers = false;
    users = {
      cardgames = {
        isSystemUser = true;
        group = "cardgames";
      };
      nixos = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
        packages = [
          pkgs.dig
        ];
      };
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
