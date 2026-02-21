{ config, inputs, lib, pkgs, pkgs-unstable, utils, ... }:

let
  nixos-kexec = pkgs.writeShellApplication {
    name = "nixos-kexec";
    text = lib.strings.fileContents "${inputs.nixos-kexec}/nixos-kexec";
  };
in

{
  boot = {
    # Emulate x86 and riscv
    binfmt.emulatedSystems = [
      "x86_64-linux"
      "riscv64-linux"
    ];

    # Enable systemd in the initramfs (required for overlay etc)
    initrd.systemd.enable = true;

    kernel.sysctl = {
      "net.core.fb_tunnels_only_for_init_net" = 2;
      "net.ipv4.conf.all.forwarding" = true;
      "net.ipv4.conf.default.forwarding" = true;
      # Enable Explicit Congestion Notification
      "net.ipv4.tcp_ecn" = 1;
      # Enable TCP Fast Open
      "net.ipv4.tcp_fastopen" = 3;
      # Enable forwarding IPv6 packets
      "net.ipv6.conf.all.forwarding" = 1;
    };

    # Use the latest Linux kernel
    kernelPackages = pkgs.linuxPackages_latest;

    # Use systemd-boot as the bootloader
    loader.systemd-boot.enable = true;
  };
  # Save several minutes per rebuild
  documentation.man.generateCaches = false;
  environment = {
    sessionVariables.SYSTEMD_EDITOR = "nvim";
    etc = {
      "tayga/plat.conf".text = ''
        # NAT64

        tun-device plat

        # The IPv4 address used for ICMPv4 messages
        ipv4-addr 192.168.8.1

        # The NAT64 prefix, IPv4 addresses can be mapped to an IPv6 address
        # within this range, as an example 192.0.2.1 would map to
        # fd09:a389:7c1e:3:c0:2:100::
        prefix fd09:a389:7c1e:3::/64

        map 192.168.8.4 fd7a:115c:a1e0:ab12:4843:cd96:625b:e016

        log drop
      '';
    };
    shellAliases.sda = "systemd-analyze security --no-pager";
  };
  fileSystems = {
    "/" = {
      device = "/dev/disk/by-uuid/b10df131-89fd-43bb-9b1a-63d10c95b817";
      options = [
        # Allow users to delete btrfs subvolumes they own
        "user_subvol_rm_allowed"
        # Don't treat suid and sgid executables as special
        "nosuid"
        # Don't tread device nodes as special
        "nodev"
        # Don't update access time
        "noatime"
        # Try to compress data using zstd
        "compress=zstd"
      ];
      fsType = "btrfs";
    };
    "/boot" = {
      device = "/dev/disk/by-uuid/A30A-BD3E";
      options = [
        # Make all files and folders unreadable and unmodifiable to users other than root
        "umask=077"

        # Mount /boot on demand
        "x-systemd.automount"

        # Unmount /boot when finished
        "x-systemd.idle-timeout=10s"
      ];
      fsType = "vfat";
    };
  };
  imports = [
    ./dns.nix
    ./firewall.nix
    ./http.nix
    ./kerberos.nix
    ./ldap.nix
    ./mail.nix
    ./nix.nix
  ];
  networking = {
    domain = "int.zandoodle.me.uk";
    fqdn = "local.zandoodle.me.uk";
    hostName = "orion";
    hosts."127.0.0.2" = [ "zandoodle.me.uk" ];
    useNetworkd = true;
  };
  programs = {
    # Disable command-not-found as it's partially incompatible with flakes.
    # command-not-found relises on a database included in the NixOS nix channel, as I'm not using nix channels, there is no such database.
    command-not-found.enable = false;
    fish = {
      enable = true;
      interactiveShellInit = ''
        fish_vi_key_bindings

        set fish_color_command blue

        ${config.systemd.package}/bin/systemctl shutdown --quiet --when=show

        begin
          if ! set -l system_status "$(${config.systemd.package}/bin/systemctl \
              is-system-running)"
            echo The system status is currently "$system_status"
          end
        end
      '';
    };
    git = {
      enable = true;
      config = {
        init.defaultBranch = "main";

        # Allow pulling from /etc/nixos as any user without any warnings
        safe.directory = "/etc/nixos";
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

          set colorcolumn=80
        '';

        # Enable nix highlighting
        packages.nix.start = with pkgs.vimPlugins; [ vim-nix ];
      };

      # Set neovim as the default editor
      defaultEditor = true;
      enable = true;
    };

    # Enable nix-index as an alternative to command-not-found
    nix-index.enable = true;

    ssh = {
      extraConfig = ''
        # Verify host keys using DNS
        VerifyHostKeyDNS yes

        Host zandoodle.me.uk *.zandoodle.me.uk
        GSSAPIAuthentication yes
        StrictHostKeyChecking yes
      '';
      package = pkgs.opensshWithKerberos;
    };

    # Enable wireshark and dumpcap
    wireshark.enable = true;
  };
  security = {
    doas.enable = true;

    # Fix run0
    pam.services.systemd-run0 = {};
    polkit.enable = true;
    sudo.enable = false;

    # Disable unused suid commands
    wrappers = {
      chsh.enable = false;
      mount.enable = false;
      umount.enable = false;
    };
  };
  services = {
    avahi = {
      allowInterfaces = [ "bridge" "shadow-lan" "guest" ];
      enable = true;
      nssmdns6 = true;
      publish = {
        addresses = true;
        domain = true;
        enable = true;
        workstation = true;
      };
      reflector = true;
    };
    bird = {
      enable = true;
      config = ''
        router id 192.168.1.201;
        protocol bgp {
          local fd7a:115c:a1e0::1a01:5208 as 65001;
          neighbor fd7a:115c:a1e0:ab12:4843:cd96:625b:e016 as 65000;
          multihop;
          ipv6 {
            export all;
            import none;
            next hop address fd27:6be8:399c:2:9c35:62ff:fe81:1b61;
          };
          ipv4 {
            export all;
            import none;
            next hop address 192.168.10.1;
          };
        }
        protocol device {

        }
        protocol direct {
          ipv4;
          ipv6;
        }
      '';
    };
    # Use dbus-broker
    dbus.implementation = "broker";
    openssh = {
      enable = true;
      settings = {
        # Disable password based authentication
        KbdInteractiveAuthentication = false;
        PasswordAuthentication = false;
        GSSAPIAuthentication = true;
        GSSAPIStrictAcceptorCheck = false;
      };
    };
    # Disable systemd-resolved
    resolved.enable = false;

    tailscale.enable = true;

    # Use userborn for user management
    userborn.enable = true;
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
    # Set the configuration revision return by nixos-version
    configurationRevision = inputs.self.rev or "dirty";

    # Enable an overlay based /etc
    etc.overlay.enable = true;

    # Set the system state version
    stateVersion = "25.11";
  };
  systemd = {
    additionalUpstreamSystemUnits = [
      # Enable soft-reboot
      "soft-reboot.target"
      "systemd-soft-reboot.service"
    ];
    network = {
      # Enable systemd-networkd
      enable = true;
      netdevs = {
        # Configure a bridge
        "10-bridge" = {
          bridgeConfig = {
            MulticastIGMPVersion = 3;
            STP = true;
            VLANFiltering = true;
          };
          netdevConfig = {
            Kind = "bridge";
            Name = "bridge";
          };
        };

        # Configure an interface to manage C-VLAN 10 (guest Wi-Fi)
        "10-guest" = {
          netdevConfig = {
            Kind = "vlan";
            MACAddress = "72:06:83:ff:5d:0c";
            Name = "guest";
          };
          vlanConfig = {
            Id = 10;
          };
        };

        "10-ipv6-tunnel" = {
          netdevConfig = {
            Kind = "ip6tnl";
            Name = "ipv6-tunnel";
          };
          tunnelConfig = {
            Independent = true;
            Local = "fd7a:115c:a1e0::1a01:5208";
            Remote = "fd7a:115c:a1e0:ab12:4843:cd96:625b:e016";
          };
        };

        # Configure the NAT64 interface
        "10-plat" = {
          netdevConfig = {
            Kind = "tun";
            Name = "plat";
          };
          # Allow tayga to use the interface without needing root
          tunConfig = {
            User = "tayga";
            Group = "tayga";
          };
        };

        # Configure an C-VLAN based overlay network
        "10-shadow-lan" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "shadow-lan";
          };
          vlanConfig.Id = 20;
        };
      };
      networks = {
        "10-bridge" = {
          address = [ "192.168.1.201/24" ];
          bridgeVLANs = [
            {
              VLAN = "10";
              PVID = 1;
              EgressUntagged = "1";
            }
            {
              VLAN = "20";
            }
          ];
          extraConfig = ''
            [IPv6RoutePrefix]
            Route=fd09:a389:7c1e::/48
            Preference=low
          '';
          ipv6SendRAConfig = {
            Managed = true;
            RouterLifetimeSec = 0;
          };
          ipv6Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:5::/64";
              Assign = true;
            }
          ];
          name = "bridge";
          networkConfig = {
            IPv6SendRA = true;
            IPv6AcceptRA = true;
            IPv6PrivacyExtensions = false;
          };
          routes = [
            {
              # Add a static route to the router
              Gateway = "192.168.1.1";
              PreferredSource = "192.168.1.201";
            }
          ];
          # Create VLANs and bind them to this interface
          vlan = [ "guest" "shadow-lan" ];
        };
        # configure the guest interface
        "10-guest" = {
          address = [ "192.168.5.201/24" "192.168.6.1/24" ];

          ipv6AcceptRAConfig.RouteMetric = 2048;
          ipv6SendRAConfig = {
            Managed = true;
            RouterPreference = "low";
          };
          ipv6Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:4::/64";
              Assign = true;
            }
          ];
          ipv6RoutePrefixes = [
            {
              Route = "fd09:a389:7c1e::/48";
            }
            {
              Route = "fd3c:32f8:5a30:2:93d6:ccd3:6c42:125c/128";
            }
          ];

          # Advertise NAT64 prefixes
          ipv6PREF64Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:3::/64";
            }
          ];

          # Don't wait for this interface to be configured
          linkConfig.RequiredForOnline = false;
          name = "guest";
          networkConfig = {
            IPv6AcceptRA = true;
            IPv6SendRA = true;
          };
        };
        "10-ipv6-tunnel" = {
          address = [ "192.168.10.1/24" "fd27:6be8:399c:2:9c35:62ff:fe81:1b61/64" ];
          name = "ipv6-tunnel";
          linkConfig.RequiredForOnline = false;
        };
        "10-enp1s0" = {
          bridge = [ "bridge" ];
          bridgeVLANs = [
            {
              VLAN = "10";
              PVID = 1;
              EgressUntagged = "1";
            }
            {
              VLAN = "20";
            }
          ];
          name = "enp1s0";
          linkConfig = {
            RequiredForOnline = false;
          };
          networkConfig = {
            # Configure the interface before the interface is connected
            ConfigureWithoutCarrier = true;
            # IPv6SendRA = true;
          };
        };
        "10-enp49s0" = {
          bridge = [ "bridge" ];
          bridgeVLANs = [
            {
              VLAN = "10";
              PVID = 1;
              EgressUntagged = "1";
            }
            {
              VLAN = "20";
            }
          ];
          name = "enp49s0";
        };

        # Configure the NAT64 interface
        "10-plat" = {
          # Add IP addresses for the link
          address = [ "192.168.8.2/32" "fd09:a389:7c1e:3:c0:a808:300::/64" ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "plat";

          # Add NAT64 prefixes
          routes = [
            {
              Destination = "192.168.8.0/24";
              # A 1480 byte IPv4 packet gets translated to a 1500 byte IPv6 packet
              MTUBytes = 1480;
            }
          ];
        };

        # Configure C-VLAN 20
        "10-shadow-lan" = {
          address = [ "fd09:a389:7c1e:1::1/64" "192.168.4.1/24" ];
          ipv6Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:1::/64";
            }
          ];
          ipv6RoutePrefixes = [
            {
              Route = "fd09:a389:7c1e::/48";
            }
          ];
          ipv6SendRAConfig = {
            Managed = true;
            RouterPreference = "low";
          };

          # Advertise NAT64 prefixes
          ipv6PREF64Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:3::/64";
            }
          ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "shadow-lan";
          networkConfig = {
            IPv6SendRA = true;
          };
          dhcpServerConfig.DNS = "_server_address";
        };
      };

      # Don't wait for a network connection
      wait-online.enable = false;
    };
    services = {
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
      plat = {
        after = [ "sys-subsystem-net-devices-plat.device" ];
        confinement.enable = true;
        restartTriggers = [ config.environment.etc."tayga/plat.conf".source ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."tayga/plat.conf".source}:/etc/tayga/plat.conf"
            "/dev/net/tun"
          ];
          CapabilityBoundingSet = "";
          DeviceAllow = "/dev/net/tun";
          ExecStart = "${lib.getExe pkgs.tayga} -d -c /etc/tayga/plat.conf";
          Group = "tayga";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          Restart = "on-failure";
          RestrictAddressFamilies = "AF_INET";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "tayga/plat";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "tayga";
        };
        wantedBy = [ "multi-user.target" ];
        wants = [ "sys-subsystem-net-devices-plat.device" ];
      };
      systemd-machined.enable = false;
      tailscaled = {
        after = [ "modprobe@tun.service" ];
        confinement = {
          enable = true;
          packages = [ config.services.tailscale.package ];
        };
        environment = {
          DBUS_SYSTEM_BUS_ADDRESS = "unix:path=/run/dbus/system_bus_socket";
          TS_DEBUG_FIREWALL_MODE = "nftables";
          TS_DEBUG_MTU = "1350";
        };
        serviceConfig = {
          UMask = "077";
          BindPaths = "/dev/net/tun";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /run/dbus/system_bus_socket /run/systemd/journal";
          User = "tailscale";
          Group = "tailscale";
          DeviceAllow = "/dev/net/tun";
          AmbientCapabilities = "CAP_NET_RAW CAP_NET_ADMIN";
          ProtectKernelModules = true;
          ProtectProc = [ "invisible" ];
          SystemCallFilter = [ "@system-service" "~@privileged" ];
          PrivateUsers = lib.mkForce false;
          RemoveIPC = true;
          NoNewPrivileges = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          ProtectSystem = lib.mkForce "strict";
          LockPersonality = true;
          LogNamespace = "tailscale";
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          ProtectClock = true;
          ProtectKernelLogs = true;
          SystemCallArchitectures = "native";
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          ProtectHome = true;
          CapabilityBoundingSet = "CAP_NET_RAW CAP_NET_ADMIN";
        };
        wants = [ "modprobe@tun.service" ];
      };
    };
    shutdownRamfs.enable = false;
  };
  users = {
    defaultUserShell = config.programs.fish.package;
    groups = {
      tailscale = {};
      tayga = {};
    };
    users = {
      max = {
        isNormalUser = true;
        extraGroups = [ "wheel" "wireshark" ];
        openssh.authorizedKeys.keys = [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmioGtxIY2vgxZi5czG/tIkSKga/91RDyTsNtc6fU3D max@max-nixos-pc"
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEy9BC0xxK5VeT/v8fUG8iQTc8PkGfYveOAz//Nfhdun max@max-nixos-workstation"
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGt0TUfmkLYBBdiTSyb/uafGoAt9eJDzTrEao0PNZKxl max@max-nixos-chromebooksd2"
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMew02x65rGiw3IK6073M1c/fJHDyQxPymDsWPHaNp6z max@max-nixos-laptop"
        ];
        packages = with pkgs; [
          btop
          dig
          dropwatch
          ethtool
          file
          gcc
          htop
          jq
          ldns
          ldns.examples
          lshw
          lsof
          nixos-kexec
          passt
          ripgrep
          slirp4netns
          tio
        ];
      };
      tailscale = {
        isSystemUser = true;
        group = "tailscale";
      };
      tayga = {
        isSystemUser = true;
        group = "tayga";
      };
    };
  };
  virtualisation.vmVariant.boot.binfmt.emulatedSystems = lib.mkForce [];
}
