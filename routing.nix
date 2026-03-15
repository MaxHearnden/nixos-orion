{ config, lib, pkgs, pkgs-unstable, ... }:

{
  environment.etc = {
    "krill.conf".text = ''
      log_type = "syslog"
      service_uri = "https://krill.zandoodle.me.uk/"
      storage_uri = "/var/lib/krill/data"
      ta_support_enabled = true
    '';
    "ta/ta.cer".source = ./ta.cer;
  };
  services = {
    bird = {
      enable = true;
      package = pkgs-unstable.${config.nixpkgs.system}.bird3.overrideAttrs (
        { patches ? [], ... }: {
          patches = patches ++ [ ./bird-aspa.patch ];
        });
      config = ''
        router id 192.168.1.201;
        roa4 table r4;
        roa6 table r6;
        aspa table at;
        filter peer_in_v4 {
          if (roa_check(r4) = ROA_INVALID) then {
            reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
          }
          if (aspa_check_upstream(at) = ASPA_INVALID) then {
            reject "Ignore ASPA invalid ", net, " for ASNs ", bgp_path;
          }
          accept;
        }
        filter peer_in_v6 {
          if (roa_check(r6) = ROA_INVALID) then {
            reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
          }
          if (aspa_check_upstream(at) = ASPA_INVALID) then {
            reject "Ignore ASPA invalid ", net, " for ASNs ", bgp_path;
          }
          accept;
        }
        filter peer_in_v4_tunnel {
          if (roa_check(r4) = ROA_INVALID) then {
            reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
          }
          if (aspa_check_upstream(at) = ASPA_INVALID) then {
            reject "Ignore ASPA invalid ", net, " for ASNs ", bgp_path;
          }
          ifname = "ipv6-tunnel";
          accept;
        }
        filter peer_in_v6_tunnel {
          if (roa_check(r6) = ROA_INVALID) then {
            reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
          }
          if (aspa_check_upstream(at) = ASPA_INVALID) then {
            reject "Ignore ASPA invalid ", net, " for ASNs ", bgp_path;
          }
          ifname = "ipv6-tunnel";
          accept;
        }
        protocol bgp pc {
          local as 65001;
          neighbor fe80::42b0:76ff:fede:79dc%bridge as 65002;
          local role provider;
          require roles on;
          ipv4 {
            export all;
            extended next hop on;
            import filter peer_in_v4;
            import table on;
          };
          ipv6 {
            export all;
            import filter peer_in_v6;
            import table on;
          };
        }
        protocol bgp pc_guest {
          local as 65001;
          neighbor fe80::42b0:76ff:fede:79dc%guest as 65002;
          local role provider;
          require roles on;
          ipv4 {
            export all;
            extended next hop on;
            import filter peer_in_v4;
            import table on;
            preference 80;
          };
          ipv6 {
            export all;
            import filter peer_in_v6;
            import table on;
            preference 80;
          };
        }
        protocol bgp pc_shadow {
          local as 65001;
          neighbor fe80::42b0:76ff:fede:79dc as 65002;
          interface "shadow-lan";
          local role provider;
          require roles on;
          ipv4 {
            export all;
            extended next hop on;
            import filter peer_in_v4;
            import table on;
            preference 90;
          };
          ipv6 {
            export all;
            import filter peer_in_v6;
            import table on;
            preference 90;
          };
        }
        protocol bgp workstation {
          local fd7a:115c:a1e0::1a01:5208 as 65001;
          neighbor fd7a:115c:a1e0:ab12:4843:cd96:625b:e016 onlink as 65000;
          interface "tailscale0";
          local role provider;
          require roles on;
          ipv4 {
            export all;
            import filter peer_in_v4_tunnel;
            import table on;
          };
          ipv6 {
            export all;
            import filter peer_in_v6_tunnel;
            import table on;
          };
        }
        protocol device {

        }
        protocol direct {
          ipv4;
          ipv6;
          interface -"tailscale*", -"ipv6-tunnel", -"lo", "*";
        }
        protocol kernel {
          ipv4 {
            export where source != RTS_DEVICE && net !~ 192.168.10.0/24;
          };
        }
        protocol kernel {
          ipv6 {
            export where source != RTS_DEVICE && net !~ fd27:6be8:399c:2::/64;
          };
        }
        protocol rpki {
          roa4 { table r4; };
          roa6 { table r6; };
          aspa { table at; };

          remote "localhost";
        }
        protocol static {
          ipv4;
          route 192.168.12.0/24 unreachable;
        }
        protocol static {
          ipv6;
          route fd09:a389:7c1e:7::/64 unreachable;
        }
      '';
    };
    routinator = {
      enable = true;
      package =
        pkgs.routinator.overrideAttrs (
          { patches ? [], ... }: {
            patches = patches ++ [ ./routinator.patch ];
          });
      settings = {
        enable-aspa = true;
        extra-tals-dir = ./tals;
        no-rir-tals = true;
        systemd-listen = true;
      };
    };
    rsyncd = {
      enable = true;
      settings = {
        globalSection = {
          address = "::";
          "socket options" = "SO_KEEPALIVE";
          "use chroot" = false;
        };
        sections = {
          ta = {
            path = "/etc/ta";
            comment = "RPKI trust anchor";
          };
          repo = {
            path = "/var/lib/krill/data/repo/rsync/current";
            comment = "RPKI repository";
          };
        };
      };
    };
  };
  systemd = {
    services = {
      krill = {
        confinement.enable = true;
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."krill.conf".source}:/etc/krill.conf"
          ];
          CapabilityBoundingSet = "";
          EnvironmentFile = "/etc/krill-admin-key";
          ExecStart =
            lib.getExe' pkgs-unstable.${config.nixpkgs.system}.krill "krill";
          Group = "krill";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "krill";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          User = "krill";
        };
        wantedBy = [ "multi-user.target" ];
      };
      rsync = {
        confinement.enable = true;
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_BIND_SERVICE";
          BindReadOnlyPaths = [
            "/etc/passwd" "/etc/group" "/var/lib/krill/data/repo/rsync"
            "${config.environment.etc."ta/ta.cer".source}:/etc/ta/ta.cer"
          ];
          CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
          DynamicUser = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          PrivateUsers = lib.mkForce false;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          RestrictNamespaces = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          ProtectHostname = true;
          LockPersonality = true;
          RestrictRealtime = true;
          ProtectHome = true;
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6";
          UMask = "077";
        };
      };
    };
    sockets.routinator = {
      listenStreams = [ "[::]:323" ];
      wantedBy = [ "routinator.service" ];
    };
  };
  users = {
    groups.krill = {};
    users.krill = {
      isSystemUser = true;
      group = "krill";
    };
  };
}
