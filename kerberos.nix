{ config, lib, utils, ... }: {
  security = {
    krb5 = {
      enable = true;
      settings = {
        libdefaults = {
          default_ccache_name = "FILE:/run/user/%{uid}/krb5cc_%{uid}";
          default_realm = "ZANDOODLE.ME.UK";
          dns_canonicalize_hostname = "fallback";
          dns_lookup_realm = true;
          permitted_enctypes = "aes256-sha2";
          rdns = false;
          spake_preauth_groups = "edwards25519";
        };
        realms = {
          "ZANDOODLE.ME.UK" = {
            disable_encrypted_timestamp = true;
          };
          "WORKSTATION.ZANDOODLE.ME.UK" = {
            disable_encrypted_timestamp = true;
          };
        };
      };
    };
    pam.krb5.enable = false;
  };
  services.kerberos_server = {
    enable = true;
    settings = {
      kdcdefaults.spake_preauth_kdc_challenge = "edwards25519";
      realms."ZANDOODLE.ME.UK" = {
        acl = [
          {
            access = "all";
            principal = "*/admin";
          }
          {
            access = "all";
            principal = "max/zandoodle.me.uk";
          }
          {
            access = "all";
            principal = "max@WORKSTATION.ZANDOODLE.ME.UK";
          }
        ];
        supported_enctypes = "aes256-sha2:normal";
        master_key_type = "aes256-sha2";
      };
    };
  };
  systemd = {
    services = {
      kadmind = {
        after = [ "kadmind.socket" ];
        confinement = {
          enable = true;
          packages = [
            config.environment.etc."krb5kdc/kdc.conf".source
            config.environment.etc."krb5.conf".source
          ];
        };
        requires = [ "kadmind.socket" ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."krb5kdc/kdc.conf".source}:/etc/krb5kdc/kdc.conf"
            "${config.environment.etc."krb5.conf".source}:/etc/krb5.conf"
          ];
          CapabilityBoundingSet = "";
          Group = "krb5";
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
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RestrictNamespaces = true;
          StateDirectory = "krb5kdc";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "krb5";
        };
        wantedBy = lib.mkForce [];
      };
      kdc = {
        after = [ "kdc.socket" ];
        confinement = {
          enable = true;
          packages = [
            config.environment.etc."krb5kdc/kdc.conf".source
            config.environment.etc."krb5.conf".source
          ];
        };
        requires = [ "kdc.socket" ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."krb5kdc/kdc.conf".source}:/etc/krb5kdc/kdc.conf"
            "${config.environment.etc."krb5.conf".source}:/etc/krb5.conf"
          ];
          CapabilityBoundingSet = "";
          ExecStart = lib.mkForce (utils.escapeSystemdExecArgs ([
            (lib.getExe' config.security.krb5.package "krb5kdc")
            "-n"
          ] ++ config.services.kerberos_server.extraKDCArgs));
          Group = "krb5";
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
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RestrictNamespaces = true;
          StateDirectory = "krb5kdc";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = lib.mkForce "simple";
          UMask = "077";
          User = "krb5";
        };
        wantedBy = lib.mkForce [];
      };
    };
    sockets = {
      kadmind = {
        listenDatagrams = [ "[::]:464" ];
        listenStreams = [ "[::]:464" "[::]:749" ];
        socketConfig.Slice = "system-kerberos-server.slice";
        wantedBy = [ "sockets.target" ];
      };
      kdc = {
        listenDatagrams = [ "[::]:88" ];
        listenStreams = [ "[::]:88" ];
        socketConfig.Slice = "system-kerberos-server.slice";
        wantedBy = [ "sockets.target" ];
      };
    };
  };
  users = {
    groups.krb5 = {};
    users.krb5 = {
      group = "krb5";
      isSystemUser = true;
    };
  };
}
