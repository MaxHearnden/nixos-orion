{ config, inputs, lib, pkgs, pkgs-unstable, utils, ... }:

let
  compsoc-website = pkgs.callPackage "${inputs.compsoc-website}/package.nix" {};
  nixos-kexec = pkgs.writeShellApplication {
    name = "nixos-kexec";
    text = lib.strings.fileContents "${inputs.nixos-kexec}/nixos-kexec";
  };
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
  boot = {
    # Emulate x86 and riscv
    binfmt.emulatedSystems = [
      "x86_64-linux"
      "riscv64-linux"
    ];

    # Enable systemd in the initramfs (required for overlay etc)
    initrd.systemd.enable = true;

    kernel.sysctl = {
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
        # The IPv6 address used for ICMPv6 messages
        ipv6-addr fd09:a389:7c1e:2::1

        # The NAT64 prefix, IPv4 addresses can be mapped to an IPv6 address
        # within this range, as an example 192.0.2.1 would map to
        # fd09:a389:7c1e:3:c0:2:100::
        prefix fd09:a389:7c1e:3::/64

        # A pool of IPv4 addresses to allocate to IPv6 addresses
        dynamic-pool 192.168.9.0/24

        # Directory to store dynamic address mappings
        data-dir /var/lib/tayga/plat
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
  imports = [ ./dns.nix ];
  networking = {
    firewall = {
      # Allow DNS, HTTP and HTTPS
      allowedUDPPorts = [ 53 54 88 443 464 41641 ];
      allowedTCPPorts = [ 25 53 54 80 88 443 464 749 ];
      extraForwardRules = ''
        iifname {plat, guest, "shadow-lan", "bridge"} oifname {plat, guest, "shadow-lan", "bridge"} accept
      '';
      extraInputRules = ''
        # Allow local devices to reach the local DNS servers (unbound and dnsmasq)
        meta l4proto {udp, tcp} th dport {55, 56, 5353} ip saddr @local_ip accept
        meta l4proto {udp, tcp} th dport {55, 56, 5353} ip6 saddr @local_ip6 accept
        tcp dport 853 reject
      '';
      # Filter packets that would have been forwarded
      filterForward = true;
      interfaces = {
        # Allow the TP-link WAP to send logs
        "\"bridge\"".allowedTCPPorts = [ 465 ];
        "\"bridge\"".allowedUDPPorts = [ 547 ];

        # Allow DHCP from managed networks
        web-vm.allowedUDPPorts = [ 67 ];
        guest.allowedUDPPorts = [ 67 547 ];
        "shadow-lan".allowedUDPPorts = [ 67 547 ];

        # Allow submissions and imaps from tailscale
        tailscale0.allowedTCPPorts = [ 465 587 993 ];
      };
    };
    fqdn = "local.zandoodle.me.uk";
    hostName = "orion";
    nftables = {
      # Disable checking the ruleset using lkl as cgroups are not enabled in lkl
      checkRuleset = false;
      enable = true;

      # Don't flush the entire ruleset and instead delete specific tables
      flushRuleset = false;
      ruleset = ''
        # Add service specific filters
        table inet services {
          set avahi {
            type cgroupsv2
          }

          set caddy {
            type cgroupsv2
          }

          set dnsdist {
            type cgroupsv2
          }

          set dnsmasq {
            type cgroupsv2
          }

          set kadmin {
            type cgroupsv2
          }

          set kdc {
            type cgroupsv2
          }

          set knot {
            type cgroupsv2
          }

          set maddy {
            type cgroupsv2
          }

          set ollama_socket {
            type cgroupsv2
          }

          set sshd {
            type cgroupsv2
          }

          set systemd_networkd {
            type cgroupsv2
          }

          set tailscaled {
            type cgroupsv2
          }

          set unbound {
            type cgroupsv2
          }

          set local_ip {
            type ipv4_addr; flags constant, interval;
            elements = {
              127.0.0.0/8,
              10.0.0.0/8,
              100.64.0.0/10,
              169.254.0.0/16,
              192.168.0.0/16,
              172.16.0.0/12,
            }
          }

          set local_ip6 {
            type ipv6_addr; flags constant, interval;
            elements = {
              ::1/128,
              fc00::/7,
              fe80::/10,
            }
          }

          chain input {
            type filter hook input priority filter + 10; policy drop;
            ct state vmap { invalid : drop, established : accept, related : accept }
            # Allow SSH from local devices
            tcp dport 22 ip saddr == @local_ip socket cgroupv2 level 2 @sshd accept
            tcp dport 22 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @sshd accept

            # Allow DNS handled by dnsdist, knot, unbound and dnsmasq
            meta l4proto {udp, tcp} th dport 53 socket cgroupv2 level 2 @dnsdist accept
            meta l4proto {udp, tcp} th dport 54 socket cgroupv2 level 2 @knot accept
            meta l4proto {udp, tcp} th dport 55 ip saddr == @local_ip socket cgroupv2 level 2 @unbound accept
            meta l4proto {udp, tcp} th dport 55 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @unbound accept
            iifname lo tcp dport 8080 socket cgroupv2 level 2 @unbound accept
            meta l4proto {udp, tcp} th dport 56 ip saddr == @local_ip socket cgroupv2 level 2 @dnsmasq accept
            meta l4proto {udp, tcp} th dport 56 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @dnsmasq accept
            meta l4proto {udp, tcp} th dport 5353 ip saddr == @local_ip socket cgroupv2 level 2 @avahi accept
            meta l4proto {udp, tcp} th dport 5353 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @avahi accept

            # Allow HTTP and HTTPS handled by caddy
            tcp dport { 80, 443 } socket cgroupv2 level 2 @caddy accept
            udp dport 443 socket cgroupv2 level 2 @caddy accept

            # Allow DHCP handled by dnsmasq
            udp dport 67 iifname { shadow-lan, guest, web-vm } socket cgroupv2 level 2 @dnsmasq accept
            udp dport 547 iifname { shadow-lan, guest, "bridge" } socket cgroupv2 level 2 @dnsmasq accept

            # Allow Kerberos
            meta l4proto {udp, tcp} th dport 88 ip saddr == @local_ip socket cgroupv2 level 4 @kdc accept
            meta l4proto {udp, tcp} th dport 88 ip6 saddr == @local_ip6 socket cgroupv2 level 4 @kdc accept
            meta l4proto {udp, tcp} th dport {464, 749} ip saddr == @local_ip socket cgroupv2 level 4 @kadmin accept
            meta l4proto {udp, tcp} th dport {464, 749} ip6 saddr == @local_ip6 socket cgroupv2 level 4 @kadmin accept

            iifname lo tcp dport 11434 socket cgroupv2 level 2 @ollama_socket accept

            udp dport 41641 socket cgroupv2 level 2 @tailscaled accept

            tcp dport 25 socket cgroupv2 level 2 @maddy accept
            iifname { lo, tailscale0 } tcp dport { 465, 587, 993 } socket cgroupv2 level 2 @maddy accept
            iifname "bridge" tcp dport {465, 587} ip saddr @local_ip socket cgroupv2 level 2 @maddy accept

            icmpv6 type != { nd-redirect, 139 } accept
            ip6 daddr fe80::/64 udp dport 546 socket cgroupv2 level 2 @systemd_networkd accept
            icmp type echo-request accept comment "allow ping"
            log prefix "CGroup Drop "
          }
        }
      '';
      extraDeletions = ''
        # Initialise services table so that the input chain can be flushed
        table inet services {
          chain input {
          }
        }
        flush chain inet services input
        delete chain inet services input
        destroy set inet services local_ip
        destroy set inet services local_ip6
      '';
      tables = {
        local-nat = {
          family = "inet";
          content = ''
            chain post {
              type nat hook postrouting priority srcnat; policy accept;
              # Don't nat packets which don't need it
              iifname { plat, guest, "shadow-lan", "bridge" } ip6 daddr == fd09:a389:7c1e::/48 accept
              iifname { plat, guest, "shadow-lan" } oifname "bridge" masquerade

              # NAT packets for router
              iifname { plat, guest, "shadow-lan" } oifname guest ip daddr 192.168.5.1 masquerade
            }
          '';
        };
        nixos-fw.content = ''
          set local_ip {
            type ipv4_addr; flags constant, interval;
            elements = {
              127.0.0.0/8,
              10.0.0.0/8,
              100.64.0.0/10,
              169.254.0.0/16,
              192.168.0.0/16,
              172.16.0.0/12,
            }
          }
          set local_ip6 {
            type ipv6_addr; flags constant, interval;
            elements = {
              ::1/128,
              fc00::/7,
              fe80::/10,
            }
          }
        '';
      };
    };
    useNetworkd = true;
  };
  nix = {
    # Make nix very low priority
    daemonIOSchedClass = "idle";
    daemonCPUSchedPolicy = "idle";

    # Run regular nix store garbage collection
    gc = {
      automatic = true;
      options = "--delete-older-than 7d";
    };
    settings = {
      # Allow only max and nix-gc to use nix
      allowed-users = [ "max" "nix-gc" ];

      # Hard link identical files together
      auto-optimise-store = true;

      # Run builds in a dedicated directory
      build-dir = "/nix/var/nix/builds";

      # Enable experimental features
      experimental-features = "cgroups nix-command flakes ca-derivations";

      # Keep all outputs of live derivations so that fewer builds and fetches are required
      keep-outputs = true;

      # Always use the nix daemon even when root
      store = "daemon";

      # Use cgroups for builds
      use-cgroups = true;
    };
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

    krb5 = {
      enable = true;
      settings = {
        libdefaults = {
          default_realm = "ZANDOODLE.ME.UK";
          dns_lookup_realm = true;
          permitted_enctypes = "aes256-sha2";
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

    pam = {
      krb5.enable = false;
      # Fix run0
      services.systemd-run0 = {};
    };
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
    # Use dbus-broker
    dbus.implementation = "broker";
    kerberos_server = {
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
    maddy = {
      config = ''
        tls {
          loader acme {
            agreed
            challenge dns-01
            dns rfc2136 {
              import /run/credentials/maddy.service/tsig.conf
              server "[::1]:54"
            }
            hostname mail.zandoodle.me.uk
          }
          protocols tls1.2 tls1.3
        }
        tls.loader.acme imap {
          agreed
          challenge dns-01
          dns rfc2136 {
            import /run/credentials/maddy.service/tsig.conf
            server "[::1]:54"
          }
          hostname imap.zandoodle.me.uk
          override_domain _acme-challenge.mail.zandoodle.me.uk
        }
        tls.loader.acme smtp {
          agreed
          challenge dns-01
          dns rfc2136 {
            import /run/credentials/maddy.service/tsig.conf
            server "[::1]:54"
          }
          hostname smtp.zandoodle.me.uk
          override_domain _acme-challenge.mail.zandoodle.me.uk
        }
        auth.pass_table local_authdb {
          table sql_table {
            driver sqlite3
            dsn credentials.db
            table_name passwords
          }
        }

        storage.imapsql local_mailboxes {
          driver sqlite3
          delivery_map regexp ".*" max@zandoodle.me.uk
          dsn imapsql.db
        }

        table.chain local_rewrites {
          optional_step regexp "(.+)\+(.+)@(.+)" "$1@$3"
          optional_step static {
            entry postmaster postmaster@zandoodle.me.uk
          }
        }

        table.chain super_auth {
          optional_step static {
            entry max@zandoodle.me.uk *
          }
        }

        table.chain sender_rewriting {
          optional_step regexp "(.+)@mail.(.+)" "$1@$2"
          step regexp "(.+)@(.+)" "$1@mail.$2"
        }

        msgpipeline local_routing {
          modify {
            replace_rcpt &local_rewrites
          }
          deliver_to &local_mailboxes
        }

        smtp tcp://0.0.0.0:25 {
          limits {
            all rate 20 1s
            all concurrency 10
          }

          dmarc yes
          check {
            require_mx_record
            dkim
            spf
          }

          source $(local_domains) {
            reject 501 5.1.8 "Use Submission for outgoing SMTP"
          }

          default_source {
            destination $(local_domains) {
              deliver_to &local_routing
            }

            default_destination {
              reject
            }
          }
        }

        submission tls://0.0.0.0:465 tcp://0.0.0.0:587 {
          limits {
            all rate 50 1s
          }

          tls {
            loader &smtp
            protocols tls1.2 tls1.3
          }

          auth &local_authdb

          # Allow tp-link@zandoodle.me.uk to send mail to tp-link-logs@zandoodle.me.uk
          source tp-link@zandoodle.me.uk {
            check {
              authorize_sender {
                prepare_email &local_rewrites
                user_to_email &super_auth
              }
            }
            destination tp-link-logs@zandoodle.me.uk {
              deliver_to &local_routing
            }
            default_destination {
              reject
            }
          }

          source dkim-test@compsoc-dev.com dkim-test@zandoodle.me.uk {
            check {
              authorize_sender {
                prepare_email &local_rewrites
                user_to_email &super_auth
              }
            }

            modify {
              dkim $(local_domains) default {
                oversign_fields Subject To From Date MIME-Version Content-Type Content-Tranfer-Encoding Reply-To Message-Id References Autocrypt Openpgp Return-Path
              }
              replace_sender &sender_rewriting
            }

            destination postmaster $(local_domains) {
              deliver_to &local_routing
            }
            default_destination {
              deliver_to &remote_queue
            }
          }

          source $(local_domains) {
            check {
              authorize_sender {
                prepare_email &local_rewrites
                user_to_email &super_auth
              }
            }

            modify {
              dkim $(local_domains) default
              replace_sender &sender_rewriting
            }

            destination postmaster $(local_domains) {
              deliver_to &local_routing
            }
            default_destination {
              deliver_to &remote_queue
            }
          }
          default_source {
            reject 501 5.1.8 "Non-local sender domain"
          }
        }

        target.remote outbound_delivery {
          limits {
            destination rate 20 1s
            destination concurrency 10
          }
          mx_auth {
            dane
            mtasts {
              cache fs
              fs_dir mtasts_cache/
            }
            local_policy {
              min_tls_level encrypted
              min_mx_level none
            }
          }
        }

        target.queue remote_queue {
          target &outbound_delivery

          autogenerated_msg_domain $(primary_domain)
          bounce {
            destination postmaster $(local_domains) {
              deliver_to &local_routing
            }
            default_destination {
              reject 550 5.0.0 "Refusing to send DSNs to non-local addresses"
            }
          }
        }

        imap tls://0.0.0.0:993 {
          auth &local_authdb
          storage &local_mailboxes
          tls {
            loader &imap
            protocols tls1.2 tls1.3
          }
        }
      '';
      enable = true;
      hostname = "mail.zandoodle.me.uk";
      localDomains = [
        "$(primary_domain)"
        "compsoc-dev.com"
        "mail.compsoc-dev.com"
        "mail.zandoodle.me.uk"
      ];
      package = pkgs.maddy.overrideAttrs (
        { tags ? [], ... }: {
          tags = tags ++ [ "libdns_rfc2136" ];
        });
      primaryDomain = "zandoodle.me.uk";
      tls.loader = null;
    };
    ollama = {
      enable = true;
      environmentVariables = {
        OLLAMA_NUM_PARALLEL = "10";
      };
      host = "[::1]";
    };
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
            MulticastQuerier = true;
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

        # Configure the NAT64 interface
        "10-plat" = {
          netdevConfig = {
            Kind = "tun";
            Name = "plat";
          };
          # Allow tayga to use the interface without needing root
          tapConfig = {
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

        # Configure an interface for the VM
        "10-web-vm" = {
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
          linkConfig.RequiredForOnline = false;
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
            DNS = "_link_local";
            EmitDNS = true;
            Managed = true;
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
          address = [ "192.168.8.0/31" "fd09:a389:7c1e:2::/127" ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "plat";

          # Add NAT64 prefixes
          routes = [
            {
              Destination = "fd09:a389:7c1e:3::/64";
            }
            {
              Destination = "192.168.9.0/24";
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
            DNS = "_link_local";
            EmitDNS = true;
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

        # Configure the web VM interface
        "10-web-vm" = {
          address = [ "192.168.2.1/30" ];
          name = "web-vm";
        };
      };

      # Don't wait for a network connection
      wait-online.enable = false;
    };
    services = {
      avahi-daemon.serviceConfig.NFTSet = "cgroup:inet:services:avahi";
      caddy.serviceConfig = {
        # Allow Caddy to bind to port 80 and port 443
        CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE";

        # Load TSIG key
        LoadCredential = map (attr: "tsig-${attr}:/run/keymgr/caddy-${attr}") [ "id" "secret" "algorithm" ];

        # Don't allow emulating Linux 2.6
        LockPersonality = true;

        # Don't allow W+X memory mappings
        MemoryDenyWriteExecute = true;

        # Add this service's cgroup to the caddy set in the services table
        NFTSet = "cgroup:inet:services:caddy";

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

      # Generate a TSIG key for caddy and maddy
      gen-tsig = {
        # Generate the TSIG key before knot, caddy or maddy starts
        before = [ "knot.service" "caddy.service" "maddy.service" ];
        requiredBy = [ "knot.service" "caddy.service" "maddy.service" ];
        # Create a mininal sandbox for gen-tsig
        confinement.enable = true;
        serviceConfig = {
          # Don't allow gen-tsig to change the current system
          CapabilityBoundingSet = "";

          # Allocate the user on service start
          DynamicUser = true;

          # Use a dedicated group
          Group = "keymgr";

          # Don't allow gen-tsig to send or receive any packets
          IPAddressDeny = "any";

          # Don't allow gen-tsig to emulate Linux 2.6
          LockPersonality = true;

          # Don't allow gen-tsig to create W+X memory mappings
          MemoryDenyWriteExecute = true;

          # Don't allow gen-tsig to access the network
          PrivateNetwork = true;

          # Create a new user namespace with only keymgr mapped in to the namespace
          PrivateUsers = true;

          # Don't allow gen-tsig to view non process files within /proc
          ProcSubset = "pid";

          # Don't allow gen-tsig to change the date
          ProtectClock = true;

          # Don't allow gen-tsig to access /home
          ProtectHome = true;

          # Don't allow gen-tsig to change the hostname
          ProtectHostname = true;

          # Don't allow gen-tsig to read or write to the kernel logs
          ProtectKernelLogs = true;

          # Don't allow gen-tsig to view processes it can't ptrace
          ProtectProc = "invisible";

          # Mount / read only
          ProtectSystem = "strict";

          # Consider gen-tsig to still be active after the main process exits
          RemainAfterExit = true;

          # Don't allow gen-tsig to create sockets
          RestrictAddressFamilies = "none";

          # Don't allow gen-tsig to create namespaces
          RestrictNamespaces = true;

          # Don't allow gen-tsig to get realtime priority
          RestrictRealtime = true;

          # Create /run/keymgr
          RuntimeDirectory = "keymgr";

          # Keep /run/keymgr after the main process exits
          RuntimeDirectoryPreserve = true;

          # Only allow aarch64 syscalls
          SystemCallArchitectures = "native";

          # Only allow typical syscalls
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];

          # This service will be considered started when the main process exits
          Type = "oneshot";

          # Make files accessible only by keymgr by default
          UMask = "077";

          # Use a dedicated user
          User = "keymgr";
        };
        script = ''
          for key in caddy knot-ds maddy; do
            # Generate a TSIG key
            ${lib.getExe' pkgs.knot-dns "keymgr"} -t $key >"/run/keymgr/$key"
          done
          for attr in id algorithm secret; do
            # Split the elements of the key into seperate files for caddy
            ${lib.getExe pkgs.yq} -r .key.[]."$attr" </run/keymgr/caddy >/run/keymgr/caddy-"$attr"
          done

          ${lib.getExe pkgs.yq} -r '"key_name " + .key.[].id' </run/keymgr/maddy >/run/keymgr/maddy-config
          ${lib.getExe pkgs.yq} -r '"key " + .key.[].secret' </run/keymgr/maddy >>/run/keymgr/maddy-config
          ${lib.getExe pkgs.yq} -r '"key_alg " + .key.[].algorithm' </run/keymgr/maddy >>/run/keymgr/maddy-config
        '';
      };
      # Get the IP address from the router
      get-IP-address = {
        # Create a minimal sandbox for this service
        confinement.enable = true;
        # Reload the DNS zone after getting the IP address
        onSuccess = [ "knot-reload.target" ];
        serviceConfig = {
          # Don't allow get-IP-address to change the system
          CapabilityBoundingSet = "";

          # Use a dedicated user
          Group = "ddns";

          # Allow get-IP-address to access the router
          IPAddressAllow = "192.168.1.1";
          IPAddressDeny = "any";

          # Don't allow get-IP-address to emulate Linux 2.6
          LockPersonality = true;

          # Don't allow get-IP-address to create W+X memory mappings
          MemoryDenyWriteExecute = true;

          # Don't allow get-IP-address to get privileges through SUID programs
          NoNewPrivileges = true;

          # Don't allow get-IP-address to access non process files within /proc
          ProcSubset = "pid";

          # Don't allow get-IP-address to change the current date
          ProtectClock = true;

          # Don't allow get-IP-address to access /home
          ProtectHome = true;

          # Don't allow get-IP-address to change the current hostname
          ProtectHostname = true;

          # Don't allow get-IP-address to read or write to the kernel logs
          ProtectKernelLogs = true;

          # Don't allow get-IP-address to view process it can't ptrace
          ProtectProc = "invisible";

          # Mount / read only
          ProtectSystem = "strict";

          # Remove all IPC objects after exiting
          RemoveIPC = true;

          # Try again on failure
          Restart = "on-failure";

          # Add a progressive slowdown to retry attempts
          RestartMaxDelaySec = "5m";
          RestartSec = "10s";
          RestartSteps = "10";
          StartLimitBurst = "20";

          # Allow get-IP-address to create netlink sockets (to get local IP
          # addresses) and IPv4 sockets to access the router
          RestrictAddressFamilies = "AF_NETLINK AF_INET";

          # Don't allow get-IP-address to create namespaces
          RestrictNamespaces = true;

          # Don't allow get-IP-address to get realtime priority
          RestrictRealtime = true;

          # Don't allow get-IP-address to create SUID files
          RestrictSUIDSGID = true;

          # Create /run/ddns when this service starts
          RuntimeDirectory = "ddns";

          # Create /var/lib/ddns when this service starts
          StateDirectory = "ddns";

          # Only allow aarch64 syscalls
          SystemCallArchitectures = "native";

          # Only allow typical syscalls
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];

          # Consider this process to have started when the main process exits
          Type = "oneshot";

          # Use a dedicated user
          User = "ddns";
        };
        script = ''
          # Enable verbose mode
          set -x

          # Get the IP address from the router
          ${lib.getExe pkgs.curl} -o /run/ddns/login.lp -v \
            http://192.168.1.1/login.lp?getSessionStatus=true

          # Extract the IP address from the reply
          ${lib.getExe pkgs.jq} -r .wanIPAddress /run/ddns/login.lp \
            >/run/ddns/IPv4-address

          # Turn it into a resource record
          printf "@ A " | ${lib.getExe' pkgs.coreutils "cat"} - /run/ddns/IPv4-address >/run/ddns/zonefile

          # Sanitize the data
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/zonefile >/run/ddns/zonefile-canonical

          # Verify that we only have one resource record
          record_count=$(${lib.getExe' pkgs.coreutils "wc"} -l --total=only /run/ddns/zonefile-canonical)
          if [ "$record_count" != 1 ]; then
            echo "Potential attack detected" >&2
            exit 1
          fi

          # Append the IPv6 records
          ${lib.getExe' pkgs.iproute2 "ip"} -json -6 address show dev bridge to 2000::/3 -temporary | ${lib.getExe pkgs.jq} -r \
            '"@ AAAA " + (.[].addr_info.[].local // empty)' >>/run/ddns/zonefile
          ${lib.getExe' pkgs.iproute2 "ip"} -json -6 address show dev bridge to 2000::/3 -temporary | ${lib.getExe pkgs.jq} -r \
            '"@ AAAA " + (.[].addr_info.[].local // empty)' >/run/ddns/zonefile-ipv6-only

          # Get the IP address for enp49s0
          ${lib.getExe' pkgs.iproute2 "ip"} -json -4 address show dev bridge | ${lib.getExe pkgs.jq} -r \
            '"@ A " + (.[].addr_info.[].local // empty)' >/run/ddns/local-zonefile
          ${lib.getExe' pkgs.iproute2 "ip"} -json -6 address show dev bridge to fc00::/7 | ${lib.getExe pkgs.jq} -r \
            '"@ AAAA " + (.[].addr_info.[].local // empty)' >>/run/ddns/local-zonefile

          # Check the zonefile is valid
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/local-zonefile

          # Get the IP address for guest
          ${lib.getExe' pkgs.iproute2 "ip"} -json -4 address show dev guest | ${lib.getExe pkgs.jq} -r \
            '"@ A " + (.[].addr_info.[].local // empty)' >/run/ddns/local-guest-zonefile

          ${lib.getExe' pkgs.iproute2 "ip"} -json -6 address show dev guest to fc00::/7 | ${lib.getExe pkgs.jq} -r \
            '"@ AAAA " + (.[].addr_info.[].local // empty)' >>/run/ddns/local-guest-zonefile

          # Get the IP address for tailscale
          ${lib.getExe' pkgs.iproute2 "ip"} -json address show dev tailscale0 | ${lib.getExe pkgs.jq} -r \
            '.[].addr_info.[]
              | if .family == "inet" then
                "@ A " + .local
              elif (.family == "inet6") and (.scope != "link") then
                "@ AAAA " + .local
              else
                empty
              end' >/run/ddns/local-tailscale-zonefile

          # Check the zonefile is valid
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/local-guest-zonefile

          # Record differences in the public IP address
          if ! ${lib.getExe' pkgs.diffutils "diff"} /run/ddns/zonefile /var/lib/ddns/zonefile; then
            cp --backup=numbered /run/ddns/zonefile "/var/lib/ddns/zonefile-$(date --iso-8601=seconds)"
          fi

          # Move the verified data from /run/ddns to /var/lib/ddns
          ${lib.getExe' pkgs.coreutils "mv"} -f /run/ddns/IPv4-address \
            /run/ddns/zonefile /run/ddns/local-zonefile /run/ddns/local-guest-zonefile /run/ddns/zonefile-ipv6-only /run/ddns/local-tailscale-zonefile /var/lib/ddns/
        '';
        unitConfig.StartLimitIntervalSec = "20m";
      };
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
      maddy.serviceConfig = {
        LoadCredential = "tsig.conf:/run/keymgr/maddy-config";
        NFTSet = "cgroup:inet:services:maddy";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        ProcSubset = "pid";
        ProtectKernelLogs = true;
        ProtectProc = "invisible";
        RemoveIPC = true;
        SystemCallArchitectures = "native";
      };
      nftables = {
        confinement = {
          enable = true;
          packages = [ pkgs.coreutils ];
        };
        serviceConfig = {
          DynamicUser = true;
          AmbientCapabilities = "CAP_NET_ADMIN";
          CapabilityBoundingSet = "CAP_NET_ADMIN";
          IPAddressDeny = "any";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          RestrictRealtime = true;
          RestrictAddressFamilies = "AF_NETLINK";
          RestrictNamespaces = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          ProtectKernelLogs = true;
          ProtectClock = true;
          LockPersonality = true;
          PrivateUsers = false;
          ProtectHostname = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          User = "nft";
          UMask = "077";
          Group = "nft";
        };
      };
      nix-daemon = {
        serviceConfig = {
          BindPaths = "/dev/kvm";
          CacheDirectory = "nix";
          CacheDirectoryMode = "0700";
          CapabilityBoundingSet = "CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_FOWNER CAP_SYS_PTRACE";
          DeviceAllow = "/dev/kvm";
          ExecStart = [
            ""
            "@${lib.getExe' config.nix.package "nix-daemon"} nix-daemon --daemon --option store local"
          ];
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProtectClock = true;
          ProtectHome = "read-only";
          ProtectKernelModules = true;
          ProtectSystem = "strict";
          ReadWritePaths = "/nix /tmp";
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          RestrictNamespaces = "cgroup ipc mnt net pid user uts";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallErrorNumber = "ENOSYS";
          SystemCallFilter = [ "@debug @system-service @mount @sandbox sethostname setdomainname" ];
          UMask = "077";
        };
        environment.XDG_CACHE_HOME = "%C";
      };
      nix-gc = {
        confinement.enable = true;
        environment.XDG_STATE_HOME = "%S/nix-gc";
        serviceConfig = {
          BindPaths = "/nix/var/nix/profiles";
          BindReadOnlyPaths = "/nix/var/nix/daemon-socket";
          CapabilityBoundingSet = "";
          Group = "nix-gc";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateNetwork = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "nix-gc";
          StateDirectoryMode = "0700";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          UMask = "077";
          User = "nix-gc";
        };
      };
      nixos-upgrade = {
        after = [ "network-online.target" ];
        path = [ pkgs.gitMinimal pkgs.kexec-tools pkgs.openssh ];
        restartIfChanged = false;
        script =
          let
            git = lib.getExe pkgs.git;
            nix = lib.getExe config.nix.package;
            nixos-rebuild = lib.getExe config.system.build.nixos-rebuild;
            setpriv = lib.getExe' pkgs.util-linux "setpriv";
          in ''
            ${git} clone -b main --single-branch /etc/nixos /run/nixos-upgrade/nixos-config
            cd /run/nixos-upgrade/nixos-config
            ${git} checkout -b update
            ${nix} flake update  --commit-lock-file --refresh
            if ${nixos-rebuild} boot --flake .?ref=update; then
              ${git} checkout main
              ${git} merge --ff update
              ${git} push
            else
              ${git} checkout main
              ${nixos-rebuild} boot --flake .?ref=main
            fi

            booted=$(${lib.getExe' pkgs.coreutils "readlink"} /run/booted-system/{kernel,kernel-modules})
            built=$(${lib.getExe' pkgs.coreutils "readlink"} /nix/var/nix/profiles/system/{kernel,kernel-modules})

            if [ "$booted" = "$built" ]; then
              ${nixos-rebuild} test --flake .
            else
              ${lib.getExe nixos-kexec} --when "1 hour left"
            fi
          '';
        serviceConfig = {
          RuntimeDirectory = "nixos-upgrade";
          Type = "oneshot";
        };
        startAt = "4:40";
        unitConfig.X-StopOnRemoval = true;
        wants = [ "network-online.target" ];
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
      sshd.serviceConfig.NFTSet = "cgroup:inet:services:sshd";
      systemd-machined.enable = false;
      systemd-networkd.serviceConfig.NFTSet = "cgroup:inet:services:systemd_networkd";
      tailscaled = {
        after = [ "modprobe@tun.service" ];
        confinement = {
          enable = true;
          packages = [ config.services.tailscale.package ];
        };
        environment = {
          TS_DEBUG_FIREWALL_MODE = "nftables";
          DBUS_SYSTEM_BUS_ADDRESS = "unix:path=/run/dbus/system_bus_socket";
        };
        serviceConfig = {
          UMask = "077";
          BindPaths = "/dev/net/tun";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /run/dbus/system_bus_socket";
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
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          ProtectClock = true;
          ProtectKernelLogs = true;
          SystemCallArchitectures = "native";
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          ProtectHome = true;
          CapabilityBoundingSet = "CAP_NET_RAW CAP_NET_ADMIN";
          NFTSet = "cgroup:inet:services:tailscaled";
        };
        wants = [ "modprobe@tun.service" ];
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
    sockets = {
      kadmind = {
        listenDatagrams = [ "[::]:464" ];
        listenStreams = [ "[::]:464" "[::]:749" ];
        socketConfig = {
          NFTSet = "cgroup:inet:services:kadmin";
          Slice = "system-kerberos-server.slice";
        };
        wantedBy = [ "sockets.target" ];
      };
      kdc = {
        listenDatagrams = [ "[::]:88" ];
        listenStreams = [ "[::]:88" ];
        socketConfig = {
          NFTSet = "cgroup:inet:services:kdc";
          Slice = "system-kerberos-server.slice";
        };
        wantedBy = [ "sockets.target" ];
      };
      ollama-proxy = {
        listenStreams = [ "/run/ollama" "127.0.0.1:11434" "[::1]:11434" ];
        socketConfig.NFTSet = "cgroup:inet:services:ollama_socket";
        wantedBy = [ "sockets.target" ];
      };
    };
    timers.get-IP-address = {
      timerConfig = {
        # Start the unit on boot
        OnBootSec = "0";
        OnUnitActiveSec = "1h";
      };
      wantedBy = [ "timers.target" ];
    };
    tmpfiles.rules = [
      "d /nix/var/nix/builds 755 root root 7d"
      "A /nix/var/nix/profiles - - - - u:nix-gc:rwx,d:u:nix-gc:rwx,m::rwx,d:m::rwx,g::rx,d:g::rx"
    ];
    shutdownRamfs.enable = false;
  };
  users = {
    defaultUserShell = config.programs.fish.package;
    groups = {
      krb5 = {};
      nix-gc = {};
      tailscale = {};
      tayga = {};
      web-vm = {};
    };
    users = {
      krb5 = {
        group = "krb5";
        isSystemUser = true;
      };
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
      nix-gc = {
        isSystemUser = true;
        group = "nix-gc";
      };
      tailscale = {
        isSystemUser = true;
        group = "tailscale";
      };
      tayga = {
        isSystemUser = true;
        group = "tayga";
      };
      web-vm = {
        group = "web-vm";
        isSystemUser = true;
      };
    };
  };
  virtualisation.vmVariant.boot.binfmt.emulatedSystems = lib.mkForce [];
}
