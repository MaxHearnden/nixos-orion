{ lib, pkgs, ... }:

let cert_obtained = pkgs.writeShellApplication {
  name = "cert_obtained";
  text = ''
    if [ "$1" = zandoodle.me.uk ] || [ "$1" = conference.zandoodle.me.uk ] || [ "$1" = uploads.zandoodle.me.uk ] || [ "$1" = proxy.zandoodle.me.uk ] || [ "$1" = lwad.xyz ]; then
      install -Dm0440 -t /var/lib/caddy/certs \
        "/var/lib/caddy/.local/share/caddy/$2/$1.crt" \
        "/var/lib/caddy/.local/share/caddy/$2/$1.key"
    fi
  '';
}; in

{
  services = {
    caddy = {
      globalConfig = ''
        events {
          on cert_obtained exec ${lib.getExe cert_obtained} {event.data.identifier} {event.data.storage_path}
        }
      '';
      virtualHosts = {
        "conference.zandoodle.me.uk".extraConfig = ''
          tls {
            issuer acme {
              dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
              profile shortlived
            }
          }

          abort
        '';
        "lwad.xyz".extraConfig = ''
          tls {
            issuer acme {
              dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
              profile shortlived
            }
          }

          abort
        '';
        "proxy.zandoodle.me.uk".extraConfig = ''
          tls {
            issuer acme {
              dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
              profile shortlived
            }
          }

          abort
        '';
        "uploads.zandoodle.me.uk".extraConfig = ''
          tls {
            issuer acme {
              dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
              profile shortlived
            }
          }

          abort
        '';
      };
    };
    coturn = {
      enable = true;
      extraConfig = ''
        verbose
      '';
      max-port = 20000;
      min-port = 10000;
      no-cli = true;
      no-tls = true;
      no-dtls = true;
      realm = "turn.zandoodle.me.uk";
      secure-stun = true;
      static-auth-secret-file = "/run/credentials/coturn.service/stun-secret";
      use-auth-secret = true;
    };
    prosody = {
      admins = [ "max@zandoodle.me.uk" ];
      allowRegistration = true;
      enable = true;
      extraConfig = ''
        c2s_direct_tls_ports = { 5223 }
        certificates = "/var/lib/caddy/certs"
        http_host = "zandoodle.me.uk"
        password_hash = "SHA-256"
        registration_invite_only = true
        s2s_direct_tls_ports = { 5270 }
        ssl = {
          cafile = "/etc/ssl/certs/ca-bundle.crt",
          curveslist = { "X25519MLKEM768", "X25519", "prime256v1", "secp384r1" }
        }
        turn_external_host = "turn.zandoodle.me.uk"
        turn_external_secret = Credential("stun-secret")
        turn_external_tcp = true
        unbound = {
          trustfile = "/var/lib/unbound/root.key"
        }
        use_dane = true

        Component "proxy.zandoodle.me.uk" "proxy65"
          proxy65_address = "zandoodle.me.uk"
          proxy65_acl = {"lwad.xyz", "zandoodle.me.uk"}
      '';
      extraModules = [
        "csi_simple"
        "invites"
        "invites_register"
        "s2s_bidi"
        "turn_external"
      ];
      httpFileShare = {
        access = [ "lwad.xyz" "zandoodle.me.uk" ];
        domain = "uploads.zandoodle.me.uk";
      };
      httpInterfaces = [ "127.0.0.1" "::1" ];
      log = ''
        {
          info = "*syslog",
        }
      '';
      modules = {
        announce = true;
        bosh = true;
        websocket = true;
        welcome = true;
      };
      muc = [
        {
          domain = "conference.zandoodle.me.uk";
        }
      ];
      s2sSecureAuth = true;
      virtualHosts = {
        default = {
          domain = "zandoodle.me.uk";
          enabled = true;
        };
        lwad = {
          domain = "lwad.xyz";
          enabled = true;
          extraConfig = ''
            disco_items = {
              { "conference.zandoodle.me.uk", "muc domain" },
              { "proxy.zandoodle.me.uk", "proxy65 service" },
              { "uploads.zandoodle.me.uk", "file sharing service" },
            }
          '';
        };
      };
    };
  };

  systemd = {
    services = {
      coturn = {
        preStart = lib.mkAfter ''
          chmod 740 /run/coturn/turnserver.cfg
          echo "external-ip=$(</var/lib/ddns/IPv4-address)/192.168.1.201" >>/run/coturn/turnserver.cfg
          chmod 640 /run/coturn/turnserver.cfg
        '';
        serviceConfig = {
          LimitNOFILE = "infinity";
          LoadCredential = "stun-secret:/run/coturn-secret/secret";
        };
      };
      gen-coturn-secret = {
        before = [ "coturn.service" "prosody.service" ];
        confinement.enable = true;
        requiredBy = [ "coturn.service" "prosody.service" ];
        serviceConfig = {
          CapabilityBoundingSet = "";
          DynamicUser = true;
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          PrivateNetwork = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          RemainAfterExit = true;
          RestrictAddressFamilies = "none";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RuntimeDirectory = "coturn-secret";
          RuntimeDirectoryPreserve = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = "oneshot";
          UMask = "077";
        };
        script = ''
          ${lib.getExe pkgs.openssl} rand -base64 32 | ${lib.getExe' pkgs.coreutils "head"} -c -1 >/run/coturn-secret/secret
        '';
        unitConfig.StopWhenUnneeded = true;
      };
      prosody.serviceConfig.LoadCredential = "stun-secret:/run/coturn-secret/secret";
    };
    targets.coturn-restart = {
      description = "restart coturn";
      conflicts = [ "coturn.service" ];
      unitConfig.StopWhenUnneeded = true;
      onSuccess = [ "coturn.service" ];
    };
  };
  users.users.prosody.extraGroups = [ "caddy" ];
}
