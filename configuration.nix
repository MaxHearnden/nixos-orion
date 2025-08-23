{ config, inputs, lib, pkgs, pkgs-unstable, ... }:

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

  gen-csp = source: pkgs.runCommandNoCC "gen-csp" {} ''
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
    binfmt.emulatedSystems = [
      "x86_64-linux"
      "riscv64-linux"
    ];
    initrd.systemd.enable = true;
    kernel.sysctl = {
      "net.ipv4.tcp_ecn" = 1;
      "net.ipv4.tcp_fastopen" = 3;
      "net.ipv6.conf.all.forwarding" = 1;
    };
    kernelPackages = pkgs.linuxPackages_latest;
    loader.systemd-boot.enable = true;
  };
  environment = {
    sessionVariables.SYSTEMD_EDITOR = "nvim";
    etc = {
      "dnsdist/dnsdist.conf".text = ''
        addLocal("0.0.0.0:53")
        addLocal("[::]:53")
        newServer({address = "127.0.0.1:54", name = "knot-dns", pool = "auth", healthCheckMode = "lazy"})
        newServer({address = "127.0.0.1:55", name = "unbound", pool = "iterative", healthCheckMode = "lazy"})
        setACL({"0.0.0.0/0", "::/0"})

        addAction(AndRule({RDRule(), NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})}), PoolAction("iterative"))
        addAction(AllRule(), LogAction("", false, true, true, false, true))
        addAction(AndRule({OrRule({QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), NotRule(NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"}))}), DropAction())
        addResponseAction(AllRule(), LogResponseAction("", true, true, false, true))
        addSelfAnsweredResponseAction(AllRule(), LogResponseAction("", true, true, false, true))
        addAction(
          AndRule({
            TCPRule(false),
            OrRule({
              NotRule(QNameSuffixRule({"zandoodle.me.uk", "compsoc-dev.com"})),
              MaxQPSIPRule(5),
            }),
          }),
          TCAction())
        addAction(AllRule(), PoolAction("auth"))
      '';
      "knot/bogus.zandoodle.me.uk.zone".text = ''
        ; A zone for testing DNSSEC support.
        ; This zone is bogus.
        $TTL 0
        @ SOA dns.zandoodle.me.uk. mail.zandoodle.me.uk. 0 0 0 0 0
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.bogus-exists.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.bogus.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /var/lib/ddns/zonefile
        @ NS dns.zandoodle.me.uk.
      '';
      "knot/compsoc-dev.com.zone".text = ''
        $TTL 600
        @ SOA dns mail 0 600 60 3600 600
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.compsoc-dev.com.
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /etc/knot/no-email.zone.include dns.compsoc-dev.com.
        $INCLUDE /var/lib/ddns/zonefile
        $INCLUDE /var/lib/ddns/zonefile dns.compsoc-dev.com.
        @ CAA 0 issuemail ";"
        @ CAA 0 issuevmc ";"
        @ CAA 0 issuewild ";"
        @ CAA 128 issue "letsencrypt.org;validationmethods=dns-01"
        @ HTTPS 1 . alpn=h3,h2
        @ NS dns
      '';
      "knot/letsencrypt.zone.include".source =
        pkgs.callPackage ./gen-TLSA.nix {} [ "ISRG_Root_X1" "ISRG_Root_X2" ];
      "knot/no-email.zone.include".text = ''
        ; Deny sending or receiving emails
        @ TXT "v=spf1 -all"
        @ MX 0 .
        _dmarc TXT "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s;fo=1"
      '';
      "knot/zandoodle.me.uk.zone".text = ''
        $TTL 600
        @ SOA dns mail 0 600 60 3600 600
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.cardgames.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.local.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.wss.cardgames.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /etc/knot/no-email.zone.include cardgames.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include dns.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include local-shadow.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include local.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include wss.cardgames.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/local-zonefile local.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile
        $INCLUDE /var/lib/ddns/zonefile cardgames.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile dns.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile wss.cardgames.zandoodle.me.uk.
        @ CAA 0 issuemail ";"
        @ CAA 0 issuevmc ";"
        @ CAA 0 issuewild ";"
        @ CAA 128 issue "letsencrypt.org;validationmethods=dns-01"
        @ HTTPS 1 . alpn=h3,h2
        @ NS dns
        bogus-exists TYPE65534 \# 0
        cardgames HTTPS 1 . alpn=h3,h2
        local HTTPS 1 . alpn=h3,h2
        local IN SSHFP 1 1 d7e54c857d4a789060cb2f84126ae04edd73eb6f
        local IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
        local IN SSHFP 4 1 9187d9131278f1a92603a1a74647e0cc98f59f6d
        local IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
        local-shadow IN SSHFP 1 1 d7e54c857d4a789060cb2f84126ae04edd73eb6f
        local-shadow IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
        local-shadow IN SSHFP 4 1 9187d9131278f1a92603a1a74647e0cc98f59f6d
        local-shadow IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
        local-shadow A 192.168.4.1
        local-shadow AAAA fd09:a389:7c1e:1::1
        wss.cardgames HTTPS 1 . alpn=h3,h2
      '';
      "resolv.conf".text = ''
        nameserver 127.0.0.1
        nameserver ::1

        options trust-ad edns0
      '';
      "tayga/tayga.conf".text = ''
        tun-device tayga
        ipv4-addr 192.168.6.1
        ipv6-addr fd80:2::1
        prefix 64:ff9b::/96
        dynamic-pool 192.168.7.0/24
        data-dir /var/lib/tayga
      '';
      "tayga/plat.conf".text = ''
        tun-device plat
        ipv4-addr 192.168.8.1
        ipv6-addr fd09:a389:7c1e:2::1
        prefix fd09:a389:7c1e:3::/64
        dynamic-pool 192.168.9.0/24
        data-dir /var/lib/tayga/plat
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
      allowedUDPPorts = [ 53 54 443 ];
      allowedTCPPorts = [ 53 54 80 443 ];
      extraForwardRules = ''
        iifname {"shadow-lan", "2-shadow-2-lan"} oifname "tayga" accept
        iifname {"shadow-lan", "2-shadow-2-lan"} oifname "plat" accept
      '';
      extraInputRules = ''
        meta l4proto {udp, tcp} th dport 55 ip saddr @local_ip accept
        meta l4proto {udp, tcp} th dport 55 ip6 saddr @local_ip6 accept
      '';
      filterForward = true;
      interfaces = {
        web-vm.allowedUDPPorts = [ 67 ];
        enp1s0.allowedUDPPorts = [ 67 ];
        shadow-lan.allowedUDPPorts = [ 67 ];
        "\"2-shadow-2-lan\"".allowedUDPPorts = [ 67 ];
      };
    };
    fqdn = "local.zandoodle.me.uk";
    hostName = "orion";
    nat = {
      enable = true;
      externalInterface = "enp49s0";
      internalInterfaces = [ "web-vm" "enp1s0" "shadow-lan" "2-shadow-2-lan" "tayga" "plat" ];
    };
    nftables = {
      checkRuleset = false;
      enable = true;
      flushRuleset = false;
      ruleset = ''
        table inet services {
          set caddy {
            type cgroupsv2
          }

          set dnsdist {
            type cgroupsv2
          }

          set knot {
            type cgroupsv2
          }

          set sshd {
            type cgroupsv2
          }

          set systemd_networkd {
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
            tcp dport 22 ip saddr == @local_ip socket cgroupv2 level 2 @sshd accept
            tcp dport 22 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @sshd accept
            meta l4proto {udp, tcp} th dport 53 socket cgroupv2 level 2 @dnsdist accept
            meta l4proto {udp, tcp} th dport 54 socket cgroupv2 level 2 @knot accept
            meta l4proto {udp, tcp} th dport 55 ip saddr == @local_ip socket cgroupv2 level 2 @unbound accept
            meta l4proto {udp, tcp} th dport 55 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @unbound accept
            tcp dport { 80, 443 } socket cgroupv2 level 2 @caddy accept
            udp dport 443 socket cgroupv2 level 2 @caddy accept
            udp dport 67 iifname { web-vm, enp1s0, shadow-lan, "2-shadow-2-lan" } socket cgroupv2 level 2 @systemd_networkd accept
            udp dport 68 iifname enp49s0 socket cgroupv2 level 2 @systemd_networkd accept
            icmpv6 type != { nd-redirect, 139 } accept
            ip6 daddr fe80::/64 udp dport 546 socket cgroupv2 level 2 @systemd_networkd accept
            icmp type echo-request accept comment "allow ping"
            log prefix "CGroup Drop "
          }
        }
      '';
      extraDeletions = ''
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
        dns = {
          family = "inet";
          content = ''
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

            chain dns-rd {
              type nat hook prerouting priority dstnat; policy accept;
              fib daddr . mark type local udp dport 53 @th,87,1 == 1 ip saddr @local_ip redirect to :55 comment "Recursion desired"
              fib daddr . mark type local udp dport 53 @th,87,1 == 1 ip6 saddr @local_ip6 redirect to :55 comment "Recursion desired"
              fib daddr . mark type local udp dport 53 redirect to :54 comment "Recursion not desired"
              fib daddr . mark type local tcp dport 53 ip saddr != @local_ip redirect to :54 comment "Tcp recursion not desired"
              fib daddr . mark type local tcp dport 53 ip6 saddr != @local_ip6 redirect to :54 comment "Tcp recursion not desired"
            }

            chain dns-rd-output {
              type nat hook output priority dstnat; policy accept;
              fib daddr . mark type local udp dport 53 @th,87,1 == 1 redirect to :55 comment "Recursion desired"
              fib daddr . mark type local udp dport 53 redirect to :54 comment "Recursion not desired"
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
    daemonIOSchedClass = "idle";
    daemonCPUSchedPolicy = "idle";
    gc = {
      automatic = true;
      options = "--delete-older-than 7d";
    };
    settings = {
      allowed-users = [ "max" "nix-gc" ];
      auto-optimise-store = true;
      build-dir = "/nix/var/nix/builds";
      experimental-features = "cgroups nix-command flakes ca-derivations";
      keep-outputs = true;
      store = "daemon";
      use-cgroups = true;
    };
  };
  programs = {
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
        packages.nix.start = with pkgs.vimPlugins; [ vim-nix ];
      };
      defaultEditor = true;
      enable = true;
    };
    nix-index.enable = true;
    ssh.extraConfig = ''
      VerifyHostKeyDNS yes
    '';
    wireshark.enable = true;
  };
  security = {
    doas.enable = true;
    pam.services.systemd-run0 = {};
    polkit.enable = true;
    sudo.enable = false;
    wrappers = {
      chsh.enable = false;
      mount.enable = false;
      umount.enable = false;
    };
  };
  services = {
    avahi.enable = false;
    dbus.implementation = "broker";
    caddy = {
      enable = true;
      globalConfig = ''
        admin "unix//run/caddy/caddy.sock"
        acme_ca "https://acme-v02.api.letsencrypt.org/directory"
        acme_dns rfc2136 {
          key_name {file./run/credentials/caddy.service/tsig-id}
          key_alg {file./run/credentials/caddy.service/tsig-algorithm}
          key {file./run/credentials/caddy.service/tsig-secret}
          server "127.0.0.1:54"
        }
        preferred_chains smallest
      '';
      logFormat = "level INFO";
      package = pkgs.caddy.withPlugins {
        plugins = ["github.com/caddy-dns/rfc2136@v1.0.0"];
        hash = "sha256-vvaCVxDMeu80v8zQY+x3ghdCRMi4Y0BE1lECUECxL+I=";
      };
      virtualHosts = {
        "compsoc-dev.com" = {
          extraConfig = ''
            encode
            header {
              Content-Security-Policy "default-src 'none'; img-src https://compsoc-dev.com/full-transparent.webp https://compsoc-dev.com/TPP.png; style-src https://compsoc-dev.com/index_final.css https://compsoc-dev.com/about_final.css; font-src https://compsoc-dev.com/orbitron.woff2 https://compsoc-dev.com/poppins.woff2 https://compsoc-dev.com/poppins-light.woff2; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy: same-origin
              Referrer-Policy no-referrer
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              X-Content-Type-Options nosniff
              X-Frame-Options DENY
            };
            root * ${compsoc-website}
            respond /.well-known/security.txt <<EOF
              Contact: https://github.com/MaxHearnden/Compsoc-Website-cobalt/issues
              Expires: 2026-07-15T20:03:40+01:00

              EOF
            file_server
          '';
        };
        "zandoodle.me.uk" = {
          extraConfig = ''
            header {
              Cross-Origin-Resource-Policy same-origin
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              X-Content-Type-Options nosniff
              X-Frame-Options DENY
              Referrer-Policy no-referrer
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            };
            respond "This is a test of config ${inputs.self}"
          '';
        };
        "wss.cardgames.zandoodle.me.uk" = {
          extraConfig = ''
            header {
              Cross-Origin-Resource-Policy same-origin
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              X-Content-Type-Options nosniff
              X-Frame-Options DENY
              Referrer-Policy no-referrer
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            };
            reverse_proxy 192.168.2.2:80
          '';
        };
        "cardgames.zandoodle.me.uk" = {
          extraConfig = ''
            encode
            header {
              Cross-Origin-Resource-Policy same-origin
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              X-Content-Type-Options nosniff
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            }
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
            header /cardgames/config.js content-type "text/javascript; charset=utf-8"
            redir / /dalmuti/
            root * ${cardgames}
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
            @denied not {
              client_ip private_ranges fe80::/10
              not client_ip 192.168.1.1
            }
            abort @denied
            header {
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              X-Content-Type-Options nosniff
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
              Cross-Origin-Resource-Policy same-origin
              X-Frame-Options DENY
              Referrer-Policy no-referrer
            };
            respond "This is a test of config ${inputs.self}"
          '';
        };
      };
    };
    knot = {
      enable = true;
      keyFiles = [ "/run/credentials/knot.service/caddy" ];
      settings = {
        acl = [
          {
            id = "caddy-acme";
            address = "127.0.0.1";
            action = "update";
            key = ["caddy"];
            update-owner = "name";
            update-owner-match = "equal";
            update-owner-name = [
              "_acme-challenge"
              "_acme-challenge.wss.cardgames"
              "_acme-challenge.cardgames"
              "_acme-challenge.local"
            ];
            update-type = "TXT";
          }
          {
            id = "transfer";
            address = [
              "10.0.0.0/8"
              "100.64.0.0/10"
              "127.0.0.0/8"
              "169.254.0.0/16"
              "192.168.0.0/16"
              "172.16.0.0/12"
              "::1/128"
              "fc00::/7"
              "fe80::/10"
            ];
            action = "transfer";
          }
        ];
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
          identity = "dns.zandoodle.me.uk";
          listen = ["0.0.0.0@54" "::@54"];
          nsid = "dns.zandoodle.me.uk";
          tcp-fastopen = true;
          tcp-reuseport = true;
        };
        submission = [
          {
            id = "unbound";
            parent = "unbound";
          }
        ];
        template = [
          {
            id = "default";
            global-module = ["mod-cookies" "mod-rrl"];
          }
        ];
        zone = [
          {
            acl = [ "transfer" ];
            domain = "bogus.zandoodle.me.uk";
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          }
          {
            acl = [ "transfer" ];
            domain = "bogus-exists.zandoodle.me.uk";
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          }
          {
            acl = [ "caddy-acme" "transfer" ];
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
            acl = [ "caddy-acme" "transfer" ];
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
          access-control = [
            "10.0.0.0/8 allow"
            "100.64.0.0/10 allow"
            "169.254.0.0/16 allow"
            "192.168.0.0/16 allow"
            "172.16.0.0/12 allow"
            "::1/128 allow"
            "fc00::/7 allow"
            "fe80::/10 allow"
          ];
          do-not-query-localhost = false;
          domain-insecure = "broadband";
          ede = true;
          interface-automatic = true;
          num-threads = 12;
          port = 55;
          private-address = [
            "10.0.0.0/8"
            "100.64.0.0/10"
            "127.0.0.0/8"
            "169.254.0.0/16"
            "172.16.0.0/12"
            "192.168.0.0/16"
            "::ffff:10.0.0.0/104"
            "::ffff:100.64.0.0/106"
            "::ffff:127.0.0.0/104"
            "::ffff:169.254.0.0/112"
            "::ffff:172.16.0.0/108"
            "::ffff:192.168.0.0/112"
            "::1/128"
            "fc00::/7"
            "fe80::/10"
          ];
          private-domain = [
            "compsoc-dev.com"
            "zandoodle.me.uk"
            "broadband"
          ];
          serve-expired = true;
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
          {
            name = "broadband";
            stub-addr = "192.168.1.1";
            stub-no-cache = true;
          }
        ];
      };
    };
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
    configurationRevision = inputs.self.rev or "dirty";
    etc.overlay.enable = true;
    stateVersion = "24.11";
  };
  systemd = {
    additionalUpstreamSystemUnits = [
      "soft-reboot.target"
      "systemd-soft-reboot.service"
    ];
    network = {
      enable = true;
      netdevs = {
        "10-plat" = {
          netdevConfig = {
            Kind = "tun";
            Name = "plat";
          };
          tapConfig = {
            User = "tayga";
            Group = "tayga";
          };
        };
        "10-shadow-lan" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "shadow-lan";
          };
          vlanConfig.Id = 20;
        };
        "10-2-shadow-2-lan" = {
          extraConfig = ''
            [VLAN]
            Id=20
            Protocol=802.1ad
          '';
          netdevConfig = {
            Kind = "vlan";
            Name = "2-shadow-2-lan";
          };
        };
        "10-tayga" = {
          netdevConfig = {
            Kind = "tun";
            Name = "tayga";
          };
          tapConfig = {
            User = "tayga";
            Group = "tayga";
          };
        };
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
        "10-enp1s0" = {
          matchConfig = {
            Name = "enp1s0";
          };
          address = [ "192.168.0.1/24" ];
          linkConfig = {
            RequiredForOnline = false;
          };
          networkConfig = {
            ConfigureWithoutCarrier = true;
            DHCPServer = true;
          };
          dhcpServerConfig = {
            DNS = "192.168.0.1";
          };
        };
        "10-enp49s0" = {
          DHCP = "yes";
          matchConfig.Name = "enp49s0";
          networkConfig.IPv6PrivacyExtensions = "kernel";
          vlan = ["shadow-lan" "2-shadow-2-lan"];
        };
        "10-plat" = {
          address = [ "192.168.8.0/31" "fd09:a389:7c1e:2::/127" ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "plat";
          routes = [
            {
              Destination = "fd09:a389:7c1e:3::/64";
            }
            {
              Destination = "192.168.9.0/24";
              MTUBytes = 1480;
            }
          ];
        };
        "10-shadow-lan" = {
          address = [ "192.168.4.1/24" "fd80:1::1/64" "fd09:a389:7c1e:1::1/64" ];
          ipv6Prefixes = [
            {
              Prefix = "fd80:1::/64";
            }
            {
              Prefix = "fd09:a389:7c1e:1::/64";
            }
          ];
          ipv6RoutePrefixes = [
            {
              Route = "64:ff9b::/96";
            }
            {
              Route = "fd80:2::/127";
            }
            {
              Route = "fd09:a389:7c1e::/48";
            }
          ];
          ipv6SendRAConfig = {
            DNS = "_link_local";
            EmitDNS = true;
            RouterLifetimeSec = 0;
          };
          ipv6PREF64Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:3::/64";
            }
          ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "shadow-lan";
          networkConfig = {
            DHCPServer = true;
            IPv6SendRA = true;
          };
          dhcpServerConfig.DNS = "_server_address";
        };
        "10-2-shadow-2-lan" = {
          address = [ "fd09:a389:7c1e:4::1/64" ];
          ipv6Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:4::/64";
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
            RouterLifetimeSec = 0;
          };
          ipv6PREF64Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:3::/64";
            }
          ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "2-shadow-2-lan";
          networkConfig = {
            DHCPServer = true;
            IPv6SendRA = true;
          };
          dhcpServerConfig.DNS = "_server_address";
        };
        "10-tayga" = {
          address = [ "192.168.6.0/31" "fd80:2::0/127" ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "tayga";
          routes = [
            {
              Destination = "64:ff9b::/96";
            }
            {
              Destination = "192.168.7.0/24";
            }
          ];
        };
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
    packages = [
      pkgs-unstable.${config.nixpkgs.system}.dnsdist
    ];
    services = {
      caddy.serviceConfig = {
        CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE";
        LoadCredential = map (attr: "tsig-${attr}:/run/keymgr/caddy-${attr}") [ "id" "secret" "algorithm" ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NFTSet = "cgroup:inet:services:caddy";
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
        RestrictAddressFamilies = "AF_INET AF_INET6 AF_NETLINK AF_UNIX";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RuntimeDirectory = "caddy";
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        UMask = "077";
      };
      dnsdist = {
        serviceConfig = {
          ExecStart = [
            ""
            "${lib.getExe pkgs-unstable.${config.nixpkgs.system}.dnsdist} --supervised --disable-syslog --config /etc/dnsdist/dnsdist.conf"
          ];
          ExecStartPre = [
            ""
            "${lib.getExe pkgs-unstable.${config.nixpkgs.system}.dnsdist} --check-config --config /etc/dnsdist/dnsdist.conf"
          ];
          NFTSet = "cgroup:inet:services:dnsdist";
          User = "dnsdist";
          Group = "dnsdist";
        };
        restartTriggers = [ config.environment.etc."dnsdist/dnsdist.conf".source ];
        startLimitIntervalSec = 0;
        wantedBy = [ "multi-user.target" ];
      };
      gen-tsig = {
        before = [ "knot.service" "caddy.service" ];
        requiredBy = [ "knot.service" "caddy.service" ];
        confinement.enable = true;
        serviceConfig = {
          DynamicUser = true;
          User = "keymgr";
          Group = "keymgr";
          IPAddressDeny = "any";
          ProcSubset = "pid";
          ProtectProc = "invisible";
          PrivateNetwork = true;
          PrivateUsers = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          RestrictRealtime = true;
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          RestrictNamespaces = true;
          SystemCallArchitectures = "native";
          CapabilityBoundingSet = "";
          ProtectClock = true;
          LockPersonality = true;
          ProtectHostname = true;
          RestrictAddressFamilies = "none";
          RuntimeDirectory = "keymgr";
          RuntimeDirectoryPreserve = true;
          MemoryDenyWriteExecute = true;
          ProtectKernelLogs = true;
          Type = "oneshot";
          RemainAfterExit = true;
          UMask = "077";
        };
        script = ''
          ${lib.getExe' pkgs.knot-dns "keymgr"} -t caddy >/run/keymgr/caddy
          for attr in id algorithm secret; do
            ${lib.getExe pkgs.yq} -r .key.[]."$attr" </run/keymgr/caddy >/run/keymgr/caddy-"$attr"
          done
        '';
      };
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
          RestrictAddressFamilies = "AF_NETLINK AF_INET";
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

          ${lib.getExe' pkgs.iproute2 "ip"} -json address show dev enp49s0 | ${lib.getExe pkgs.jq} -r \
            '.[].addr_info.[]
              | if .family == "inet" then
                "@ A " + .local
              elif (.family == "inet6") and (.scope != "link") then
                "@ AAAA " + .local
              else
                empty
              end' >/run/ddns/local-zonefile

          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/local-zonefile

          ${lib.getExe' pkgs.coreutils "mv"} -f /run/ddns/IPv4-address \
            /run/ddns/zonefile /run/ddns/local-zonefile /var/lib/ddns/
        '';
        unitConfig.StartLimitIntervalSec = "20m";
        wantedBy = ["multi-user.target"];
      };
      knot.serviceConfig = {
        LoadCredential = "caddy:/run/keymgr/caddy";
        LimitNOFILE = "infinity";
        NFTSet = "cgroup:inet:services:knot";
      };
      knot-reload = {
        after = [ "knot.service" ];
        confinement.enable = true;
        requires = [ "knot.service" ];
        restartTriggers = map (zone: config.environment.etc."knot/${zone}".source) [
          "bogus.zandoodle.me.uk.zone"
          "compsoc-dev.com.zone"
          "no-email.zone.include"
          "letsencrypt.zone.include"
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
          User = "knot";
        };
        wantedBy = [ "multi-user.target" ];
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
      plat = {
        after = [ "sys-subsystem-net-devices-plat.device" ];
        confinement.enable = true;
        restartTriggers = [ config.environment.etc."tayga/tayga.conf".source ];
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
      tayga = {
        after = [ "sys-subsystem-net-devices-tayga.device" ];
        confinement.enable = true;
        restartTriggers = [ config.environment.etc."tayga/tayga.conf".source ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."tayga/tayga.conf".source}:/etc/tayga/tayga.conf"
            "/dev/net/tun"
          ];
          CapabilityBoundingSet = "";
          DeviceAllow = "/dev/net/tun";
          ExecStart = "${lib.getExe pkgs.tayga} -d -c /etc/tayga/tayga.conf";
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
          StateDirectory = "tayga";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "tayga";
        };
        wantedBy = [ "multi-user.target" ];
        wants = [ "sys-subsystem-net-devices-tayga.device" ];
      };
      unbound.serviceConfig.NFTSet = "cgroup:inet:services:unbound";
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
    tmpfiles.rules = [
      "d /nix/var/nix/builds 755 root root 7d"
      "A /nix/var/nix/profiles - - - - u:nix-gc:rwx,d:u:nix-gc:rwx,m::rwx,d:m::rwx,g::rx,d:g::rx"
    ];
    shutdownRamfs.enable = false;
  };
  users = {
    defaultUserShell = config.programs.fish.package;
    groups = {
      ddns = {};
      dnsdist = {};
      nix-gc = {};
      tayga = {};
      web-vm = {};
    };
    users = {
      ddns = {
        group = "ddns";
        isSystemUser = true;
      };
      dnsdist = {
        group = "dnsdist";
        isSystemUser = true;
      };
      max = {
        isNormalUser = true;
        extraGroups = [ "wheel" "wireshark" ];
        openssh.authorizedKeys.keys = [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmioGtxIY2vgxZi5czG/tIkSKga/91RDyTsNtc6fU3D max@max-nixos-pc"
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEy9BC0xxK5VeT/v8fUG8iQTc8PkGfYveOAz//Nfhdun max@max-nixos-workstation"
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGt0TUfmkLYBBdiTSyb/uafGoAt9eJDzTrEao0PNZKxl max@max-nixos-chromebooksd2"
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
          ripgrep
          tio
        ];
      };
      nix-gc = {
        isSystemUser = true;
        group = "nix-gc";
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
