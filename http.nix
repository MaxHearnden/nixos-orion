{ config, inputs, lib, pkgs, ... }:

let
  compsoc-website = pkgs.callPackage "${inputs.compsoc-website}/package.nix" {};
  web-vm = pkgs.nixos [ ./vm.nix { _module.args.inputs = inputs; } ];
  cardgames =
    if builtins.pathExists "${inputs.cardgames}/cardgames" then
      pkgs.nix-gitignore.gitignoreSourcePure [
        ".git*"
        "Cpp"
        "dominion/img/domonion-parts.png"
        "LICENSE"
      ] inputs.cardgames
    else
      pkgs.emptyDirectory;

  gen-csp = source: pkgs.runCommand "gen-csp" {} ''
    ${lib.getExe inputs.cspc.packages.${config.nixpkgs.system}.default} ${
      if builtins.isPath source then
        source
      else
        pkgs.writeText "CSP.yaml" source
    } $out
  '';
in

{
  services = {
    caddy = {
      enable = true;
      globalConfig = ''
        # Enable admin API
        admin "unix//run/caddy/caddy.sock"

        # Use Let's Encrypt to get certificates using ACME
        acme_ca "https://acme-v02.api.letsencrypt.org/directory"

        # Add credentials to change TXT records at the _acme-challenge subdomains
        dns rfc2136 {
          key_name {file./run/credentials/caddy.service/tsig-id}
          key_alg {file./run/credentials/caddy.service/tsig-algorithm}
          key {file./run/credentials/caddy.service/tsig-secret}
          server "[::1]:54"
        }

        # Use (marginally) more secure public keys
        key_type p384

        # Prefer the smallest chain (X2)
        preferred_chains smallest
      '';
      logFormat = "level INFO";
      package = pkgs.caddy.withPlugins {
        plugins = [ "github.com/caddy-dns/rfc2136@v1.0.0" ];
        hash = "sha256-tVJf4lxv00TxdtCAoJhNs8tgRWiXw3poN4S+NlPhGwU=";
      };
      virtualHosts = {
        "compsoc-dev.com" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            # Enable compression
            encode

            header {
              # Add a restrictive Content Security Policy
              Content-Security-Policy "default-src 'none'; img-src https://compsoc-dev.com/full-transparent.webp https://compsoc-dev.com/TPP.png; style-src https://compsoc-dev.com/index_final.css https://compsoc-dev.com/about_final.css; font-src https://compsoc-dev.com/orbitron.woff2 https://compsoc-dev.com/poppins.woff2 https://compsoc-dev.com/poppins-light.woff2; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy: same-origin

              # Make browsers not send a referrer header when following links
              Referrer-Policy no-referrer

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff
              # Disable this content being inside a frame
              X-Frame-Options DENY
            }
            root * ${compsoc-website}

            # Add a security.txt file
            respond /.well-known/security.txt <<EOF
              Contact: https://github.com/MaxHearnden/Compsoc-Website-cobalt/issues
              Expires: 2026-07-15T20:03:40+01:00

              EOF
            file_server
          '';
        };
        "zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            header {
              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy same-origin

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff

              # Disable this content being inside a frame
              X-Frame-Options DENY

              # Make browsers not send a referrer header when following links
              Referrer-Policy no-referrer

              # Add a restrictive Content Security Policy
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            }

            respond "This is a test of config ${inputs.self}"
          '';
        };
        "wss.cardgames.zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            header {
              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy same-origin

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff

              # Disable this content being inside a frame
              X-Frame-Options DENY

              # Make browsers not send a referrer header when following links
              Referrer-Policy no-referrer

              # Add a restrictive Content Security Policy
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            }

            # Forward all requests to the VM
            reverse_proxy 192.168.2.2:80
          '';
        };
        "cardgames.zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            # Compress all data
            encode
            header {
              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy same-origin

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff

              # Disable this content being inside a frame
              X-Frame-Options DENY

              # Make browsers not send a referrer header when following links
              Referrer-Policy no-referrer
            }

            # Add Content Security Policies
            route {
              header Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              header /dalmuti/ Content-Security-Policy {file.${gen-csp ''
                default-src: null
                script-src:
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"
                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-3.6.0.min.js
                      - jquery-ui.min.js
                    cardgames/:
                      - config.js
                      - background.js
                      - cards.js
                      - cardutils.js
                      - dalmutistate.js
                      - mcts.js
                      - AIBot.js
                      - simplebot.js
                      - gameengine.js
                      - bot.js
                      - superbot.js
                    dalmuti/dalmuti:
                      - card.js
                      - .js
                style-src: https://cardgames.zandoodle.me.uk/dalmuti/dalmuti.css
                img-src:
                  https://cardgames.zandoodle.me.uk/dalmuti/img/:
                    - dalmuti3.png
                    - speaker.png
                    - dalmuti-thumb.png
                media-src:
                  https://cardgames.zandoodle.me.uk/dalmuti/sound/chord.mp3
                connect-src:
                  wss://wss.cardgames.zandoodle.me.uk/hello
                base-uri: null
                frame-ancestors: null
                form-action: null
              ''}}
              header /diplomacy/ Content-Security-Policy {file.${gen-csp ''
                default-src: null
                script-src:
                  # digest of https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"

                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-1.7.min.js
                      - jquery-ui.min.js
                    cardgames/:
                      - config.js
                      - background.js
                      - cardutils.js
                    diplomacy/diplomacy.js: ""
                style-src:
                  https://cardgames.zandoodle.me.uk/:
                    - diplomacy/diplomacy.css
              ''}}
              header /dominion/ Content-Security-Policy {file.${gen-csp ''
                default-src: null
                script-src:
                  # digest of https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"

                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-1.7.min.js
                      - jquery-ui.min.js
                    cardgames/:
                      - config.js
                      - background.js
                      - cards.js
                      - cardutils.js
                      - dalmutistate.js
                      - mcts.js
                      - AIBot.js
                      - simplebot.js
                      - gameengine.js
                      - bot.js
                      - superbot.js
                style-src: https://cardgames.zandoodle.me.uk/dominion/dominion.css
                img-src:
                  https://cardgames.zandoodle.me.uk/:
                    img/speaker.png: ""
                    dominion/img/:
                      - dominion.jpg
                      - dominion-parts.png
                connect-src:
                  wss://wss.cardgames.zandoodle.me.uk/hello
                base-uri: null
                frame-ancestors: null
                form-action: null
              ''}}
              header /hearts/ Content-Security-Policy {file.${gen-csp ''
                default-src: null
                script-src:
                  # digest of https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"

                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-3.6.0.min.js
                      - jquery-ui.min.js
                    cardgames/:
                      - config.js
                      - background.js
                      - cards.js
                      - cardutils.js
                      - heartsstate.js
                      - mcts.js
                      - AIBot.js
                      - simplebot.js
                      - gameengine.js
                      - bot.js
                      - superbot.js
                    hearts/hearts.js: ""
                img-src:
                  https://cardgames.zandoodle.me.uk/img/:
                    - cards.png
                    - cards-thumb.png
                    - speaker.png
                media-src: https://cardgames.zandoodle.me.uk/hearts/sound/chord.mp3
                style-src: https://cardgames.zandoodle.me.uk/hearts/hearts.css
                connect-src:
                  wss://wss.cardgames.zandoodle.me.uk/hello
                base-uri: null
                frame-ancestors: null
                form-action: null
              ''}}
              header /quacks/ Content-Security-Policy {file.${gen-csp ''
                default-src: null
                script-src:
                  # digest of https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"

                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-3.6.0.min.js
                      - jquery-ui.min.js
                    cardgames/:
                      - config.js
                      - background.js
                      - tokens.js
                      - cardutils.js
                      - mcts.js
                      - AIBot.js
                      - simplebot.js
                      - gameengine.js
                      - bot.js
                      - superbot.js
                      - quackspotinfo.js
                      - quacksstate.js
                    quacks/quacks.js: ""
                style-src:
                  https://cardgames.zandoodle.me.uk/:
                    - library/jquery-ui.min.css
                    - quacks/quacks.css
                img-src:
                  https://cardgames.zandoodle.me.uk/:
                    library/images/ui-icons_:
                      - 444444_256x240.png
                      - 555555_256x240.png
                      - 777620_256x240.png
                      - 777777_256x240.png
                      - cc0000_256x240.png
                      - ffffff_256x240.png
                    quacks/img/:
                      - Pot.jpg
                      - book-thumb300.png
                      - book-thumb500.png
                      - tokens-thumb47.png
                      - tokens.png
                connect-src:
                  wss://wss.cardgames.zandoodle.me.uk/hello
                base-uri: null
                frame-ancestors: null
                form-action: null
              ''}}
              header /sheriff/ Content-Security-Policy {file.${gen-csp ''
                base-uri: null
                connect-src: wss://wss.cardgames.zandoodle.me.uk/hello
                default-src: null
                form-action: null
                frame-ancestors: null
                img-src:
                  https://cardgames.zandoodle.me.uk/:
                    - sheriff/img/sheriff_cards.png
                    - img/speaker.png
                script-src:
                  # digest of https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"

                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-1.7.min.js
                      - jquery-ui.min.js

                    cardgames/:
                      - config.js
                      - cards.js
                      - cardutils.js
                      - mcts.js
                      - AIBot.js
                      - simplebot.js
                      - gameengine.js
                      - bot.js
                      - superbot.js
                      - sheriffstate.js
                    sheriff/:
                      - sheriffcard.js
                      - sheriff.js
                style-src:
                  https://cardgames.zandoodle.me.uk/sheriff/sheriff.css
              ''}}
              header /spyfall/ Content-Security-Policy {file.${gen-csp ''
                base-uri: null
                connect-src: wss://wss.cardgames.zandoodle.me.uk/hello
                default-src: null
                form-action: null
                frame-ancestors: null
                img-src:
                  https://cardgames.zandoodle.me.uk/spyfall/img/:
                    - spyfall.png
                    - back.png
                script-src:
                  # digest of https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js
                  "": "'sha256-srkrqNQxQ5PTxynPlMErZaHbKkH7Z2slLwYPjq/dLv0='"

                  https://cardgames.zandoodle.me.uk/:
                    library/:
                      - jquery-1.7.min.js
                      - jquery-ui.min.js

                    cardgames/:
                      - config.js
                      - cards.js
                      - cardutils.js
                      - gameengine.js
                      - spyfallstate.js
                    spyfall/:
                      - spyfallcard.js
                      - spyfall.js
                style-src:
                  https://cardgames.zandoodle.me.uk/spyfall/spyfall.css
              ''}}
            }

            # Set the content type of the javascript config shim
            header /cardgames/config.js content-type "text/javascript; charset=utf-8"
            redir / /dalmuti/
            root * ${cardgames}

            # Add a javascript content shim
            respond /cardgames/config.js <<EOF
              // Config shim for cardgames.zandoodle.me.uk
              var config = {
                server: "wss://wss.cardgames.zandoodle.me.uk/hello",
              }

              if (typeof module !== 'undefined') {
                module.exports = config
              }
              EOF
            file_server
          '';
        };
        "local.zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            @denied not {
              client_ip private_ranges fe80::/10
              not client_ip 192.168.1.1
            }
            abort @denied
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
            respond "This is a test of config ${inputs.self}"
          '';
        };
        "mta-sts.compsoc-dev.com" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
            respond /.well-known/mta-sts.txt <<EOF
              version: STSv1
              mode: enforce
              max_age: 31557600
              mx: mail.zandoodle.me.uk

              EOF
          '';
        };
        "mta-sts.mail.compsoc-dev.com" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
            respond /.well-known/mta-sts.txt <<EOF
              version: STSv1
              mode: enforce
              max_age: 31557600
              mx: mail.zandoodle.me.uk

              EOF
          '';
        };
        "mta-sts.mail.zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
            respond /.well-known/mta-sts.txt <<EOF
              version: STSv1
              mode: enforce
              max_age: 31557600
              mx: mail.zandoodle.me.uk

              EOF
          '';
        };
        "mta-sts.zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
            respond /.well-known/mta-sts.txt <<EOF
              version: STSv1
              mode: enforce
              max_age: 31557600
              mx: mail.zandoodle.me.uk

              EOF
          '';
        };
        "ollama.compsoc-dev.com" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            @denied not {
              client_ip private_ranges 100.64.0.0/10
            }
            abort @denied
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }

            respond /api/pull "You can't pull models" 403
            respond /api/delete "You can't delete models" 403

            reverse_proxy unix//run/ollama {
              header_up Host localhost
            }
          '';
        };
        "recursive.dns.zandoodle.me.uk" = {
          extraConfig = ''
            tls {
              issuer acme {
                dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
                profile shortlived
              }
            }
            @denied not client_ip private_ranges 100.64.0.0/10
            abort @denied

            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
            reverse_proxy h2c://[::1]:8080
          '';
        };
      };
    };
    ollama = {
      enable = true;
      environmentVariables = {
        OLLAMA_NUM_PARALLEL = "10";
      };
      host = "[::1]";
    };
  };
  systemd = {
    network = {
      netdevs."10-web-vm" = {
        # Configure an interface for the VM
        netdevConfig = {
          Kind = "tap";
          Name = "web-vm";
        };

        # Allow QEMU to use the interface without root
        tapConfig = {
          Group = "web-vm";
          User = "web-vm";
        };
      };
      networks."10-web-vm" = {
        # Configure the web VM interface
        address = [ "192.168.2.1/30" ];
        name = "web-vm";
      };
    };
    services = {
      caddy.serviceConfig = {
        # Allow Caddy to bind to port 80 and port 443
        CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE";

        # Load TSIG key
        LoadCredential = map (attr: "tsig-${attr}:/run/keymgr/caddy-${attr}") [ "id" "secret" "algorithm" ];

        # Don't allow emulating Linux 2.6
        LockPersonality = true;

        # Don't allow W+X memory mappings
        MemoryDenyWriteExecute = true;

        # Only allow Caddy to access pid files within /proc
        ProcSubset = "pid";

        # Don't allow Caddy to set the date
        ProtectClock = true;

        # Don't allow Caddy access to cgroups
        ProtectControlGroups = true;

        # Don't allow Caddy access to /home
        ProtectHome = true;

        # Don't allow Caddy to change the hostname
        ProtectHostname = true;

        # Don't allow Caddy to read or write the kernel logs
        ProtectKernelLogs = true;

        # Don't allow Caddy to load kernel modules
        ProtectKernelModules = true;

        # Don't allow Caddy to change /sys
        ProtectKernelTunables = true;

        # Don't allow Caddy to see processes which it can't ptrace
        ProtectProc = "invisible";

        # Mount / read only
        ProtectSystem = "strict";

        # Remove sysvipc data owned by Caddy after this service exists
        RemoveIPC = true;

        # Only allow Caddy to create IPv4, IPv6, netlink and unix sockets
        RestrictAddressFamilies = "AF_INET AF_INET6 AF_NETLINK AF_UNIX";

        # Don't allow Caddy to create namespaces
        RestrictNamespaces = true;

        # Don't allow Caddy to get realtime priority
        RestrictRealtime = true;

        # Don't allow Caddy to create SUID files
        RestrictSUIDSGID = true;

        # Create /run/caddy when this service starts
        RuntimeDirectory = "caddy";

        # Only allow aarch64 syscalls
        SystemCallArchitectures = "native";

        # Only allow typical syscalls
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];

        # Set the default umask
        UMask = "077";
      };
      ollama = {
        postStart = ''
          for i in $(seq 60); do
            ${pkgs.netcat}/bin/nc -z ::1 11434 && exit
            sleep 1
          done
        '';
        serviceConfig = {
          PrivateNetwork = true;
          IPAddressAllow = "localhost";
          IPAddressDeny = "any";
        };
        unitConfig.StopWhenUnneeded = true;
        wantedBy = lib.mkForce [];
      };
      ollama-proxy = {
        after = [ "ollama.service" "ollama-proxy.socket" ];
        confinement.enable = true;
        requires = [ "ollama.service" "ollama-proxy.socket" ];
        serviceConfig = {
          CapabilityBoundingSet = "";
          DynamicUser = true;
          ExecStart = "${pkgs.systemd}/lib/systemd/systemd-socket-proxyd ::1:11434 --exit-idle-time=5min";
          Group = "ollama-proxy";
          IPAddressAllow = "localhost";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          RestrictAddressFamilies = "AF_INET AF_INET6";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "ollama-proxy";
        };
        unitConfig.JoinsNamespaceOf = "ollama.service";
      };
      web-vm = {
        confinement.enable = true;
        serviceConfig = {
          BindReadOnlyPaths = [ "/dev/kvm" "/dev/net/tun" ];
          CapabilityBoundingSet = "";
          DeviceAllow = [ "/dev/kvm" "/dev/net/tun" ];
          ExecStart = "${lib.getExe web-vm.config.system.build.vm}";
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
    sockets.ollama-proxy = {
      listenStreams = [ "/run/ollama" "127.0.0.1:11434" "[::1]:11434" ];
      wantedBy = [ "sockets.target" ];
    };
  };
  users = {
    groups.web-vm = {};
    users.web-vm = {
      group = "web-vm";
      isSystemUser = true;
    };
  };
}
