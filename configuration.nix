{ config, lib, pkgs, ... }: {
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
  networking.hostName = "orion";
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
  };
  services = {
    knot = {
      enable = true;
      settings = {
        server = {
          listen = ["0.0.0.0" "::"];
        };
        zone = [
          {
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
    xserver = {
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
          RestrictAddressFamilies = "AF_INET";
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
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -E A -c /run/ddns/zonefile >/run/ddns/zonefile-canonical
          record_count=$(${lib.getExe' pkgs.coreutils "wc"} -l --total=only /run/ddns/zonefile-canonical)
          if [ "$record_count" != 1 ]; then
            echo "Potential attack detected" >&2
            exit 1
          fi

          ${lib.getExe' pkgs.coreutils "mv"} -f /run/ddns/IPv4-address /run/ddns/zonefile /var/lib/ddns/
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
    users = {
      ddns = {
        isSystemUser = true;
        group = "ddns";
      };
      max = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
        openssh.authorizedKeys.keys = [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmioGtxIY2vgxZi5czG/tIkSKga/91RDyTsNtc6fU3D max@max-nixos-pc"
        ];
        packages = with pkgs; [
          btop
          htop
          dig
        ];
      };
    };
    groups.ddns = {};
  };
}
