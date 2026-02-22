{ lib, pkgs, ... }:

let cert_obtained = pkgs.writeShellApplication {
  name = "cert_obtained";
  text = ''
    if [ "$1" = zandoodle.me.uk ] || [ "$1" = conference.zandoodle.me.uk ] || [ "$1" = uploads.zandoodle.me.uk ]; then
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
    prosody = {
      admins = [ "max@zandoodle.me.uk" ];
      enable = true;
      extraConfig = ''
        c2s_direct_tls_ports = { 5223 }
        certificates = "/var/lib/caddy/certs"
        password_hash = "SHA-256"
        s2s_direct_tls_ports = { 5270 }
        ssl = {
          curveslist = { "X25519MLKEM768", "X25519", "prime256v1", "secp384r1" }
        }
        unbound = {
          trustfile = "/var/lib/unbound/root.key"
        }
        use_dane = true
      '';
      extraModules = [
        "admin_shell"
        "bosh"
        "websocket"
      ];
      httpFileShare = {
        domain = "uploads.zandoodle.me.uk";
      };
      httpInterfaces = [ "127.0.0.1" "::1" ];
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
      };
    };
  };
  users.users.prosody.extraGroups = [ "caddy" ];
}
