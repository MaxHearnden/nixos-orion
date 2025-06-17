{ config, inputs, lib, pkgs, ... }: {
  boot = {
    initrd.systemd.enable = true;
    kernelPackages = pkgs.linuxPackages_latest;
    loader.systemd-boot.enable = true;
  };
  environment.etc = {
    "knot/zandoodle.me.uk.zone".text = ''
      $TTL 600
      @ SOA dns mail 0 600 60 3600 600
      @ NS dns
      @ CAA 128 issue ";"
      $INCLUDE /var/lib/ddns/zonefile
      $INCLUDE /var/lib/ddns/zonefile dns.zandoodle.me.uk.
    '';
  };
  fileSystems = {
    "/" = {
      device = "/dev/disk/by-uuid/b10df131-89fd-43bb-9b1a-63d10c95b817";
      options = [
        "user_subvol_rm_allowed"
        "nosuid"
        "nodev"
        "noatime"
        "compress=zstd"
      ];
      fsType = "btrfs";
    };
    "/boot" = {
      device = "/dev/disk/by-uuid/A30A-BD3E";
      options = [ "umask=077" "x-systemd.automount" "x-systemd.idle-timeout=10s" ];
      fsType = "vfat";
    };
  };
  networking = {
    firewall = {
      allowedUDPPorts = [ 53 ];
      allowedTCPPorts = [ 53 ];
    };
    hostName = "orion";
    nftables.enable = true;
    resolvconf.useLocalResolver = true;
  };
  nix = {
    gc = {
      automatic = true;
      options = "--delete-older-than 7d";
    };
    settings = {
      experimental-features = "nix-command flakes";
      keep-outputs = true;
    };
  };
  programs = {
    git = {
      enable = true;
      config = {
        init.defaultBranch = "main";
        safe.directory = "/home/max/nixos-config";
        user = {
          email = "maxoscarhearnden@gmail.com";
          name = "MaxHearnden";
        };
      };
    };
    neovim = {
      configure = {
        customRC = ''
          set mouse=a
          set shiftwidth=2
          set expandtab
          inoremap {<CR> {<CR>}<Esc>ko
          inoremap [<CR> [<CR>]<Esc>ko
          inoremap (<CR> (<CR>)<Esc>ko
        '';
        packages.nix.start = with pkgs.vimPlugins; [ vim-nix ];
      };
      defaultEditor = true;
      enable = true;
    };
    wireshark.enable = true;
  };
  services = {
    dnsdist = {
      enable = true;
      listenPort = 53;
      extraConfig = ''
        addLocal("[::]:53")
        newServer({address = "127.0.0.1:54", name = "knot-dns", pool = "auth"})
        newServer({address = "127.0.0.1:55", name = "unbound", pool = "iterative"})
        setACL({"0.0.0.0/0", "::/0"})

        addAction(AndRule({RDRule(), NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})}), PoolAction("iterative"))
        addAction(AllRule(), PoolAction("auth"))
      '';
    };
    knot = {
      enable = true;
      settings = {
        policy = [
          {
            id = "porkbun";
            single-type-signing = true;
          }
        ];
        server = {
          listen = ["0.0.0.0@54" "::@54"];
        };
        zone = [
          {
            dnssec-policy = "porkbun";
            dnssec-signing = true;
            domain = "zandoodle.me.uk";
            file = "/etc/knot/zandoodle.me.uk.zone";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          }
        ];
      };
    };
    openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };
    unbound = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        server = {
          do-not-query-localhost = false;
          port = 55;
        };
        stub-zone = [
          {
            name = "zandoodle.me.uk";
            stub-addr = "127.0.0.1@54";
            stub-no-cache = true;
          }
        ];
      };
    };
    xserver = {
      autorun = false;
      enable = true;
      desktopManager.gnome.enable = true;
      displayManager.gdm = {
        autoSuspend = false;
        enable = true;
      };
    };
  };
  system = {
    autoUpgrade = {
      allowReboot = true;
      enable = true;
      flags = [ "--no-write-lock-file" ];
      flake = "git+file:///home/max/nixos-config";
    };
    etc.overlay.enable = true;
    stateVersion = "24.11";
  };
  systemd = {
    services = {
      get-IP-address = {
        confinement.enable = true;
        serviceConfig = {
          BindReadOnlyPaths = [ "-/run/knot/knot.sock" ];
          CapabilityBoundingSet = "";
          Group = "ddns";
          IPAddressAllow = "192.168.1.1";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_UNIX AF_INET";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RuntimeDirectory = "ddns";
          StateDirectory = "ddns";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = "oneshot";
          User = "ddns";
        };
        script = ''
          set -x
          ${lib.getExe pkgs.curl} -o /run/ddns/login.lp -v \
            http://192.168.1.1/login.lp?getSessionStatus=true
          ${lib.getExe pkgs.jq} -r .wanIPAddress /run/ddns/login.lp \
            >/run/ddns/IPv4-address
          printf "@ A " | ${lib.getExe' pkgs.coreutils "cat"} - /run/ddns/IPv4-address >/run/ddns/zonefile
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/zonefile >/run/ddns/zonefile-canonical
          record_count=$(${lib.getExe' pkgs.coreutils "wc"} -l --total=only /run/ddns/zonefile-canonical)
          if [ "$record_count" != 1 ]; then
            echo "Potential attack detected" >&2
            exit 1
          fi

          ${lib.getExe' pkgs.coreutils "mv"} -f /run/ddns/IPv4-address /run/ddns/zonefile /var/lib/ddns/
          ${lib.getExe' pkgs.knot-dns "knotc"} zone-reload zandoodle.me.uk.
        '';
      };
      knot.reloadTriggers = [ config.environment.etc."knot/zandoodle.me.uk.zone".source ];
    };
    timers.get-IP-address = {
      timerConfig = {
        OnUnitActiveSec = "1h";
      };
      wantedBy = [ "timers.target" ];
    };
    shutdownRamfs.enable = false;
  };
  users = {
    groups.ddns = {};
    users = {
      ddns = {
        extraGroups = [ "knot" ];
        group = "ddns";
        isSystemUser = true;
      };
      max = {
        isNormalUser = true;
        extraGroups = [ "wheel" "wireshark" ];
        openssh.authorizedKeys.keys = [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmioGtxIY2vgxZi5czG/tIkSKga/91RDyTsNtc6fU3D max@max-nixos-pc"
        ];
        packages = with pkgs; [
          btop
          dig
          htop
          inputs.nixos-kexec.packages.aarch64-linux.default
          ldns
          ldns.examples
        ];
      };
    };
  };
}
