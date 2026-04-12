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
          patches = patches ++ [ ./bird-mpls-fix.patch ];
        });
      config = ''
        router id 192.168.1.201;
        roa4 table r4;
        roa6 table r6;
        aspa table at;
        mpls domain mdom;
        mpls table mtab;
        vpn4 table vtab4;
        vpn6 table vtab6;
        function verify_in(bool upstream) {
          case net.type {
            NET_IP4: {
              if (roa_check(r4) = ROA_INVALID) then {
                reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
              }
            }
            NET_IP6: {
              if (roa_check(r6) = ROA_INVALID) then {
                reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
              }
            }
          }
          if (aspa_check(at, bgp_path, upstream) = ASPA_INVALID) then {
            reject "Ignore ASPA invalid ", net, " for ASN ", bgp_path.last;
          }
        }
        filter provider_in {
          if !defined(bgp_otc) then {
            bgp_otc = bgp_path.first;
          }
          verify_in(false);
          accept;
        }
        filter peer_in {
          if !defined(bgp_otc) then {
            bgp_otc = bgp_path.first;
          }
          if bgp_otc != bgp_path.first then reject;
          verify_in(true);
          accept;
        }
        filter customer_in {
          if defined(bgp_otc) then {
            reject;
          }
          verify_in(true);
          accept;
        }
        filter complex_in {
          verify_in(false);
          accept;
        }
        filter provider_out {
          if defined(bgp_otc) then {
            reject;
          }
          accept;
        }
        filter peer_out {
          if defined(bgp_otc) then {
            reject;
          }
          bgp_otc = 65001;
          accept;
        }
        filter customer_out {
          if !defined(bgp_otc) then {
            bgp_otc = 65001;
          }
          accept;
        }

        template bgp pc {
          local as 65001;
          local role peer;
          enforce first as on;
        }
        template bgp pc_untrusted from pc {
          neighbor fe80::9ab7:85ff:fe22:bd4e as 65002;
          ipv4 {
            export all;
            extended next hop on;
            import all;
            import table on;
          };
          ipv6 {
            export all;
            import all;
            import table on;
          };
        }
        protocol bgp pc_internet from pc_untrusted {
          interface "internet";
          ipv4 {
            preference 90;
          };
          ipv6 {
            preference 90;
          };
        }
        protocol bgp pc_guest from pc_untrusted {
          interface "guest";
          ipv4 {
            preference 70;
          };
          ipv6 {
            preference 70;
          };
        }
        protocol bgp pc_shadow from pc_untrusted {
          interface "shadow-lan";
          ipv4 {
            preference 80;
          };
          ipv6 {
            preference 80;
          };
        }
        protocol bgp pc_mpls from pc {
          interface "mpls";
          local fe80::1;
          neighbor fe80::5 as 65002;
          ipv4 mpls {
            export filter peer_out;
            extended next hop on;
            import filter peer_in;
            import table on;
            require extended next hop on;
          };
          ipv6 mpls {
            export filter peer_out;
            import filter peer_in;
            import table on;
          };
          mpls {
            label policy aggregate;
          };
          vpn4 mpls {
            export filter peer_out;
            extended next hop on;
            import filter peer_in;
            import table on;
            require extended next hop on;
          };
          vpn6 mpls {
            export filter peer_out;
            import filter peer_in;
            import table on;
          };
        }
        template bgp mpls_tunnel {
          local fe80::1 as 65001;
          local role provider;
          enforce first as on;
          ipv4 mpls {
            export filter customer_out;
            extended next hop on;
            import filter customer_in;
            import table on;
            require extended next hop on;
          };
          ipv6 mpls {
            export filter customer_out;
            import filter customer_in;
            import table on;
          };
          mpls {label policy aggregate;};
          vpn4 mpls {
            export filter customer_out;
            extended next hop on;
            import filter customer_in;
            import table on;
            require extended next hop on;
          };
          vpn6 mpls {
            export filter customer_out;
            import filter customer_in;
            import table on;
          };
        }
        protocol bgp workstation from mpls_tunnel {
          neighbor fe80::2 as 65000;
          interface "workstation-tnl";
        }
        protocol bgp chromebook from mpls_tunnel {
          neighbor fe80::3 as 65003;
          interface "chromebook-tnl";
        }
        protocol bgp laptop from mpls_tunnel {
          neighbor fe80::4 as 65004;
          interface "laptop-tnl";
        }
        protocol device {

        }
        protocol direct {
          ipv4 {
            import filter {
              if net = 192.168.6.0/24 then reject;
              accept;
            };
          };
          ipv6;
          interface "internet", "guest", "shadow-lan";
        }
        protocol kernel {
          ipv4 {
            export filter {
              if source = RTS_DEVICE then
                reject;
              krt_prefsrc = 192.168.11.1;
              accept;
            };
          };
        }
        protocol kernel {
          ipv6 {
            export filter {
              if source = RTS_DEVICE then
                reject;
              krt_prefsrc = fd09:a389:7c1e:6::1;
              accept;
            };
          };
        }
        protocol kernel {
          mpls {export all;};
        }
        protocol rpki {
          roa4 { table r4; };
          roa6 { table r6; };
          aspa { table at; };

          remote "localhost";
        }
        protocol static {
          ipv4;
          route 192.168.11.1/32 unreachable;
        }
        protocol static {
          ipv6;
          route fd09:a389:7c1e:6::1/128 unreachable;
          route fd09:a389:7c1e::/48 unreachable;
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
