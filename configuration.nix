{ config, inputs, lib, pkgs, ... }: {
  boot = {
    initrd.systemd.enable = true;
    kernel.sysctl."net.ipv4.tcp_ecn" = 1;
    kernelPackages = pkgs.linuxPackages_latest;
    loader.systemd-boot.enable = true;
  };
  environment = {
    etc = {
      "knot/bogus.zandoodle.me.uk.zone".text = ''
        $TTL 0
        @ SOA dns.zandoodle.me.uk. mail.zandoodle.me.uk. 0 0 0 0 0
        @ NS dns.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /var/lib/ddns/zonefile
      '';
      "knot/compsoc-dev.com.zone".text = ''
        $TTL 600
        @ SOA dns mail 0 600 60 3600 600
        @ NS dns
        @ CAA 128 issue ";"
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /etc/knot/no-email.zone.include dns.compsoc-dev.com.
        $INCLUDE /var/lib/ddns/zonefile
        $INCLUDE /var/lib/ddns/zonefile dns.compsoc-dev.com.
      '';
      "knot/no-email.zone.include".text = ''
        @ TXT "v=spf1 -all"
        @ MX 0 .
        _dmarc TXT "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s;fo=1"
      '';
      "knot/zandoodle.me.uk.zone".text = ''
        $TTL 600
        @ SOA dns mail 0 600 60 3600 600
        @ NS dns
        @ CAA 128 issue ";"
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /etc/knot/no-email.zone.include dns.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile
        $INCLUDE /var/lib/ddns/zonefile dns.zandoodle.me.uk.
      '';
    };
    shellAliases.sda = "systemd-analyze security --no-pager";
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
      allowedTCPPorts = [ 53 80 ];
      filterForward = true;
      interfaces.web-vm.allowedUDPPorts = [ 67 ];
    };
    hostName = "orion";
    nat = {
      enable = true;
      externalInterface = "enp49s0";
      forwardPorts = [
        {
          destination = "192.168.2.2:80";
          proto = "tcp";
          sourcePort = 80;
          loopbackIPs = [ "192.168.1.167" ];
        }
      ];
      internalInterfaces = [ "web-vm" ];
    };
    nftables.enable = true;
    resolvconf.useLocalResolver = true;
    useNetworkd = true;
  };
  nix = {
    gc = {
      automatic = true;
      options = "--delete-older-than 7d";
    };
    settings = {
      allowed-users = [ "max" ];
      use-cgroups = true;
      experimental-features = "cgroups nix-command flakes";
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
    avahi.enable = false;
    dnsdist = {
      enable = true;
      listenPort = 53;
      extraConfig = ''
        addLocal("[::]:53")
        newServer({address = "127.0.0.1:54", name = "knot-dns", pool = "auth"})
        newServer({address = "127.0.0.1:55", name = "unbound", pool = "iterative"})
        setACL({"0.0.0.0/0", "::/0"})

        addAction(AndRule({RDRule(), NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})}), PoolAction("iterative"))
        addAction(AndRule({TCPRule(false), NotRule(QNameSuffixRule({"zandoodle.me.uk", "compsoc-dev.com"}))}), DropAction())
        addAction(AllRule(), PoolAction("auth"))
      '';
    };
    knot = {
      enable = true;
      settings = {
        policy = [
          {
            id = "porkbun";
            ksk-submission = "unbound";
            rrsig-lifetime = "12h";
            rrsig-refresh = "4h";
            single-type-signing = true;
          }
        ];
        remote = [
          {
            id = "unbound";
            address = "127.0.0.1@55";
          }
        ];
        server = {
          listen = ["127.0.0.1@54" "::1@54"];
        };
        submission = [
          {
            id = "unbound";
            parent = "unbound";
          }
        ];
        zone = [
          {
            domain = "bogus.zandoodle.me.uk";
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          }
          {
            dnssec-policy = "porkbun";
            dnssec-signing = true;
            domain = "compsoc-dev.com";
            file = "/etc/knot/compsoc-dev.com.zone";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          }
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
    resolved.enable = false;
    unbound = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        server = {
          do-not-query-localhost = false;
          ede = true;
          port = 55;
        };
        stub-zone = [
          {
            name = "zandoodle.me.uk";
            stub-addr = "127.0.0.1@54";
            stub-no-cache = true;
          }
          {
            name = "compsoc-dev.com";
            stub-addr = "127.0.0.1@54";
            stub-no-cache = true;
          }
        ];
      };
    };
    # xserver = {
    #   autorun = false;
    #   enable = true;
    #   desktopManager.gnome.enable = true;
    #   displayManager.gdm = {
    #     autoSuspend = false;
    #     enable = true;
    #   };
    # };
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
    network = {
      enable = true;
      netdevs = {
        # "10-vm-bridge" = {
        #   netdevConfig = {
        #     Kind = "bridge";
        #     Name = "vm-bridge";
        #   };
        # };
        "10-web-vm" = {
          netdevConfig = {
            Kind = "tap";
            Name = "web-vm";
          };
          tapConfig = {
            Group = "web-vm";
            User = "web-vm";
          };
        };
      };
      networks = {
        "10-web-vm" = {
          matchConfig = {
            Name = "web-vm";
          };
          networkConfig = {
            Address = "192.168.2.1/30";
            DHCPServer = true;
          };
          dhcpServerConfig = {
            DNS = "192.168.2.1";
          };
          dhcpServerStaticLeases = [
            {
              Address = "192.168.2.2";
              MACAddress = "52:54:00:12:34:56";
            }
          ];
        };
      };
      wait-online.enable = false;
    };
    services = {
      get-IP-address = {
        confinement.enable = true;
        onSuccess = [ "knot-reload.target" ];
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
          Restart = "on-failure";
          RestartMaxDelaySec = "5m";
          RestartSec = "10s";
          RestartSteps = "10";
          StartLimitBurst = "20";
          StartLimitIntervalSec = "20m";
          RestrictAddressFamilies = "AF_UNIX AF_INET";
          RestrictNamespaces = true;
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
        '';
        wantedBy = ["multi-user.target"];
      };
      knot.serviceConfig = {
        IPAddressDeny = "any";
        IPAddressAllow = "localhost";
      };
      knot-reload = {
        after = [ "knot.service" ];
        confinement.enable = true;
        requires = [ "knot.service" ];
        restartTriggers = map (zone: config.environment.etc."knot/${zone}".source) [
          "bogus.zandoodle.me.uk.zone"
          "compsoc-dev.com.zone"
          "no-email.zone.include"
          "zandoodle.me.uk.zone"
        ];
        serviceConfig = {
          BindReadOnlyPaths = "/run/knot/knot.sock";
          CapabilityBoundingSet = "";
          ExecStart = "${lib.getExe' pkgs.knot-dns "knotc"} zone-reload";
          Group = "knot";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateNetwork = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemainAfterExit = true;
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = "oneshot";
          UMask = "077";
          User = "knot";
        };
        wantedBy = [ "multi-user.target" ];
      };
      nix-daemon = {
        serviceConfig = {
          CapabilityBoundingSet = "CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_FOWNER CAP_SYS_PTRACE";
          ProtectSystem = "strict";
          BindPaths = "/dev/kvm";
          DeviceAllow = "/dev/kvm";
          ReadWritePaths = "/nix /tmp";
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          SystemCallFilter = [ "@debug @system-service @mount @sandbox sethostname setdomainname" ];
          SystemCallErrorNumber = "ENOSYS";
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProtectClock = true;
          ProtectHome = "read-only";
          ProtectKernelModules = true;
          RestrictSUIDSGID = true;
          RestrictNamespaces = "user net mnt ipc pid uts";
          RestrictRealtime = true;
          CacheDirectory = "nix";
          CacheDirectoryMode = "0700";
        };
        environment.XDG_CACHE_HOME = "%C";
      };
      nscd.serviceConfig = {
        CapabilityBoundingSet = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = lib.mkForce true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
      };
      systemd-machined.enable = false;
      web-vm = {
        confinement.enable = true;
        serviceConfig = {
          BindReadOnlyPaths = [ "/dev/kvm" "/dev/net/tun" ];
          CapabilityBoundingSet = "";
          DeviceAllow = [ "/dev/kvm" "/dev/net/tun" ];
          ExecStart = "${lib.getExe inputs.self.nixosConfigurations.web-vm.config.system.build.vm}";
          Group = "web-vm";
          IPAddressDeny = "any";
          LockPersonality = true;
          NoNewPrivileges = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "none";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RestrictNamespaces = true;
          RuntimeDirectory = "web-vm";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          SystemCallErrorNumber = "ENOSYS";
          Type = "exec";
          UMask = "077";
          User = "web-vm";
        };
        wantedBy = [ "multi-user.target" ];
      };
    };
    targets.knot-reload = {
      description = "Restart knot-reload service";
      conflicts = [ "knot-reload.service" ];
      unitConfig.StopWhenUnneeded = true;
      onSuccess = [ "knot-reload.service" ];
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
    groups = {
      ddns = {};
      web-vm = {};
    };
    users = {
      ddns = {
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
          tio
        ];
      };
      web-vm = {
        group = "web-vm";
        isSystemUser = true;
      };
    };
  };
}
