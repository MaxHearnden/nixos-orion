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
