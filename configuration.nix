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
    # Emulate x86 and riscv
    binfmt.emulatedSystems = [
      "x86_64-linux"
      "riscv64-linux"
    ];

    # Enable systemd in the initramfs (required for overlay etc)
    initrd.systemd.enable = true;

    kernel.sysctl = {
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
  environment = {
    sessionVariables.SYSTEMD_EDITOR = "nvim";
    etc = {
      # Configuration for the dnsdist DNS load balancer
      "dnsdist/dnsdist.conf".text = ''
        -- listen on all IPv4 and IPv6 addresses
        addLocal("0.0.0.0:53")
        addLocal("[::]:53")

        -- Add local DNS servers
        newServer({address = "127.0.0.1:54", name = "knot-dns", pool = "auth", healthCheckMode = "lazy"})
        newServer({address = "127.0.0.1:55", name = "unbound", pool = "iterative", healthCheckMode = "lazy"})
        newServer({address = "127.0.0.1:56", name = "dnsmasq", pool = "dnsmasq", healthCheckMode = "lazy"})

        -- Allow connections from all IP addresses
        setACL({"0.0.0.0/0", "::/0"})

        -- Forward recursive queries to the recursive resolver (unbound)
        addAction(AndRule({RDRule(), NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})}), PoolAction("iterative"))

        -- Forward local queries for home.arpa and associated rDNS domains to dnsmasq
        addAction(AndRule({QNameSuffixRule({"home.arpa", "168.192.in-addr.arpa", "d.f.ip6.arpa"}), NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})}), PoolAction("dnsmasq"))

        -- Filter out non-local zone transfers
        addAction(AndRule({OrRule({QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), NotRule(NetmaskGroupRule({"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"}))}), DropAction())

        -- Provide some rate limiting
        addAction(
          AndRule({
            TCPRule(false),
            OrRule({
              NotRule(QNameSuffixRule({"zandoodle.me.uk", "compsoc-dev.com"})),
              MaxQPSIPRule(5),
            }),
          }),
          TCAction())

        -- Forward all remaining queries to the authoritative DNS server (knot)
        addAction(AllRule(), PoolAction("auth"))
      '';
      "knot/bogus.zandoodle.me.uk.zone".text = ''
        ; A zone for testing DNSSEC support.
        ; This zone is bogus.
        $TTL 0
        @ SOA dns.zandoodle.me.uk. mail.zandoodle.me.uk. 0 0 0 0 0

        ; DANE testing
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.bogus-exists.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.bogus.zandoodle.me.uk.

        ; Setup DMARC and SPF for this domain
        $INCLUDE /etc/knot/no-email.zone.include

        ; Advertise our public IP address as the IP address for this domain
        $INCLUDE /var/lib/ddns/zonefile
        @ NS dns.zandoodle.me.uk.
      '';
      "knot/compsoc-dev.com.zone".text = ''
        $TTL 600
        @ SOA dns.zandoodle.me.uk. mail 0 600 60 3600 600

        ; Advertise DANE
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.compsoc-dev.com.

        ; Setup DMARC and SPF for this domain
        $INCLUDE /etc/knot/no-email.zone.include

        ; Advertise our public IP address as the IP address for compsoc-dev.com and dns.compsoc-dev.com
        $INCLUDE /var/lib/ddns/zonefile

        ; Setup certificate authority restrictions
        @ CAA 0 issuemail ";"
        @ CAA 0 issuevmc ";"
        @ CAA 0 issuewild ";"
        ; Only Let's Encrypt can issue for this domain and only using the dns-01 validation method
        @ CAA 128 issue "letsencrypt.org;validationmethods=dns-01"

        ; Advertise HTTP/2 and HTTP/3 support
        @ HTTPS 1 . alpn=h3,h2

        ; Advertise the authoritative nameserver
        @ NS dns.zandoodle.me.uk.
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

        ; Setup DANE for this domain
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.cardgames.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.local.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.wss.cardgames.zandoodle.me.uk.
        $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.zandoodle.me.uk.

        ; Setup SPF and DMARC for this domain
        $INCLUDE /etc/knot/no-email.zone.include
        $INCLUDE /etc/knot/no-email.zone.include cardgames.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include dns.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include dot-check\..zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include local-shadow.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include local.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include local-guest.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include multi-string-check.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include null-check.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include ttl-check.zandoodle.me.uk.
        $INCLUDE /etc/knot/no-email.zone.include wss.cardgames.zandoodle.me.uk.

        ; Advertise IP addresses for this domain
        $INCLUDE /var/lib/ddns/local-zonefile local.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/local-guest-zonefile local-guest.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile
        $INCLUDE /var/lib/ddns/zonefile cardgames.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile dns.zandoodle.me.uk.
        $INCLUDE /var/lib/ddns/zonefile wss.cardgames.zandoodle.me.uk.

        ; Setup certificate authority restrictions for this domain
        @ CAA 0 issuemail ";"
        @ CAA 0 issuevmc ";"
        @ CAA 0 issuewild ";"
        ; Only Let's Encrypt can issue for this domain and only using the dns-01 validation method
        @ CAA 128 issue "letsencrypt.org;validationmethods=dns-01"

        ; Advertise HTTP/2 and HTTP/3 support for zandoodle.me.uk
        @ HTTPS 1 . alpn=h3,h2
        @ NS dns

        ; Setup an extant domain for DNSSEC testing
        bogus-exists TYPE65534 \# 0

        ; Advertise HTTP/2 and HTTP/3 support for cardgames.zandoodle.me.uk
        cardgames HTTPS 1 . alpn=h3,h2

        dot-check\. txt dot\ check

        ; Advertise HTTP/2 and HTTP/3 support for local.zandoodle.me.uk
        local HTTPS 1 . alpn=h3,h2

        ; Public SSH key fingerprints for local domains
        local IN SSHFP 1 1 d7e54c857d4a789060cb2f84126ae04edd73eb6f
        local IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
        local IN SSHFP 4 1 9187d9131278f1a92603a1a74647e0cc98f59f6d
        local IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
        local-guest IN SSHFP 1 1 d7e54c857d4a789060cb2f84126ae04edd73eb6f
        local-guest IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
        local-guest IN SSHFP 4 1 9187d9131278f1a92603a1a74647e0cc98f59f6d
        local-guest IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
        local-shadow IN SSHFP 1 1 d7e54c857d4a789060cb2f84126ae04edd73eb6f
        local-shadow IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
        local-shadow IN SSHFP 4 1 9187d9131278f1a92603a1a74647e0cc98f59f6d
        local-shadow IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81

        local-shadow A 192.168.10.1
        local-shadow AAAA fd09:a389:7c1e:4::1

        multi-string-check TXT string 1 string 2

        ; Check that null bytes within TXT records are handled correctly
        null-check TXT "\000"

        ; Add a zero ttl record for testing DNS resolvers
        ttl-check 0 txt ttl\ check

        ; Advertise HTTP/2 and HTTP/3 support for wss.cardgames.zandoodle.me.uk
        wss.cardgames HTTPS 1 . alpn=h3,h2
      '';
      "resolv.conf".text = ''
        # Use the local DNS resolver
        nameserver 127.0.0.1
        nameserver ::1

        # Trust the AD (authentic data) flag and use EDNS(0)
        options trust-ad edns0
      '';
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
  networking = {
    firewall = {
      # Allow DNS, HTTP and HTTPS
      allowedUDPPorts = [ 53 54 443 ];
      allowedTCPPorts = [ 53 54 80 443 ];
      extraForwardRules = ''
        # Allow packets from 2-shadow-2-lan to reach the NAT64 interface
        iifname "2-shadow-2-lan" oifname "plat" accept
      '';
      extraInputRules = ''
        # Allow local devices to reach the local DNS servers (unbound and dnsmasq)
        meta l4proto {udp, tcp} th dport {55, 56} ip saddr @local_ip accept
        meta l4proto {udp, tcp} th dport {55, 56} ip6 saddr @local_ip6 accept
        tcp dport 853 reject
      '';
      # Filter packets that would have been forwarded
      filterForward = true;
      interfaces = {
        # Allow DHCP from managed networks
        web-vm.allowedUDPPorts = [ 67 ];
        guest.allowedUDPPorts = [ 67 ];
        "\"2-shadow-2-lan\"".allowedUDPPorts = [ 67 547 ];
      };
    };
    fqdn = "local.zandoodle.me.uk";
    hostName = "orion";
    nat = {
      # Translate network addresses from local interfaces to the internet
      enable = true;
      externalInterface = "bridge";
      internalInterfaces = [ "2-shadow-2-lan" "plat" ];
    };
    nftables = {
      # Disable checking the ruleset using lkl as cgroups are not enabled in lkl
      checkRuleset = false;
      enable = true;

      # Don't flush the entire ruleset and instead delete specific tables
      flushRuleset = false;
      ruleset = ''
        # Add service specific filters
        table inet services {
          set caddy {
            type cgroupsv2
          }

          set dnsdist {
            type cgroupsv2
          }

          set dnsmasq {
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
            # Allow SSH from local devices
            tcp dport 22 ip saddr == @local_ip socket cgroupv2 level 2 @sshd accept
            tcp dport 22 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @sshd accept

            # Allow DNS handled by dnsdist, knot, unbound and dnsmasq
            meta l4proto {udp, tcp} th dport 53 socket cgroupv2 level 2 @dnsdist accept
            meta l4proto {udp, tcp} th dport 54 socket cgroupv2 level 2 @knot accept
            meta l4proto {udp, tcp} th dport 55 ip saddr == @local_ip socket cgroupv2 level 2 @unbound accept
            meta l4proto {udp, tcp} th dport 55 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @unbound accept
            meta l4proto {udp, tcp} th dport 56 ip saddr == @local_ip socket cgroupv2 level 2 @dnsmasq accept
            meta l4proto {udp, tcp} th dport 56 ip6 saddr == @local_ip6 socket cgroupv2 level 2 @dnsmasq accept

            # Allow HTTP and HTTPS handled by caddy
            tcp dport { 80, 443 } socket cgroupv2 level 2 @caddy accept
            udp dport 443 socket cgroupv2 level 2 @caddy accept

            # Allow DHCP handled by dnsmasq
            udp dport 67 iifname { "2-shadow-2-lan", guest, web-vm } socket cgroupv2 level 2 @dnsmasq accept
            udp dport 547 iifname "2-shadow-2-lan" socket cgroupv2 level 2 @dnsmasq accept

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

              # Redirect DNS queries to the appropriate service when possible

              # Redirect recusive queries from local devices to unbound
              fib daddr . mark type local udp dport 53 @th,87,1 == 1 ip saddr @local_ip redirect to :55 comment "Recursion desired"
              fib daddr . mark type local udp dport 53 @th,87,1 == 1 ip6 saddr @local_ip6 redirect to :55 comment "Recursion desired"

              # Redirect queries from non local devices to knot
              fib daddr . mark type local udp dport 53 ip saddr != @local_ip redirect to :54 comment "Recursion not desired"
              fib daddr . mark type local udp dport 53 ip6 saddr != @local_ip6 redirect to :54 comment "Recursion not desired"
              fib daddr . mark type local tcp dport 53 ip saddr != @local_ip redirect to :54 comment "Tcp recursion not desired"
              fib daddr . mark type local tcp dport 53 ip6 saddr != @local_ip6 redirect to :54 comment "Tcp recursion not desired"
            }

            chain dns-rd-output {
              type nat hook output priority dstnat; policy accept;
              # Redirect recusive queries from ourself to unbound
              fib daddr . mark type local udp dport 53 @th,87,1 == 1 redirect to :55 comment "Recursion desired"
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

    # Verify host keys using DNS
    ssh.extraConfig = ''
      VerifyHostKeyDNS yes
    '';

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
    avahi.enable = false;
    caddy = {
      enable = true;
      globalConfig = ''
        # Enable admin API
        admin "unix//run/caddy/caddy.sock"

        # Use Let's Encrypt to get certificates using ACME
        acme_ca "https://acme-v02.api.letsencrypt.org/directory"

        # Add credentials to change TXT records at the _acme-challenge subdomains
        acme_dns rfc2136 {
          key_name {file./run/credentials/caddy.service/tsig-id}
          key_alg {file./run/credentials/caddy.service/tsig-algorithm}
          key {file./run/credentials/caddy.service/tsig-secret}
          server "127.0.0.1:54"
        }

        # Prefer the smallest chain (X2)
        preferred_chains smallest
      '';
      logFormat = "level INFO";
      package = pkgs.caddy.withPlugins {
        plugins = ["github.com/caddy-dns/rfc2136@v1.0.0"];
        hash = "sha256-OuZeeKsAItmWtKwDYDnh+zZv/ZjiIFHRdAFhMDBFnqI=";
      };
      virtualHosts = {
        "compsoc-dev.com" = {
          extraConfig = ''
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
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff
              # Disable this content being inside a frame
              X-Frame-Options DENY
            };
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
            header {
              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy same-origin

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains"

              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff

              # Disable this content being inside a frame
              X-Frame-Options DENY

              # Make browsers not send a referrer header when following links
              Referrer-Policy no-referrer

              # Add a restrictive Content Security Policy
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            };

            respond "This is a test of config ${inputs.self}"
          '';
        };
        "wss.cardgames.zandoodle.me.uk" = {
          extraConfig = ''
            header {
              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy same-origin

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains"

              # Disable content sniffing (detecion of javascript)
              X-Content-Type-Options nosniff

              # Disable this content being inside a frame
              X-Frame-Options DENY

              # Make browsers not send a referrer header when following links
              Referrer-Policy no-referrer

              # Add a restrictive Content Security Policy
              Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            };

            # Forward all requests to the VM
            reverse_proxy 192.168.2.2:80
          '';
        };
        "cardgames.zandoodle.me.uk" = {
          extraConfig = ''
            # Compress all data
            encode
            header {
              # Add a Cross Origin Resource Policy
              Cross-Origin-Resource-Policy same-origin

              # Force HTTPS use on this domain and all subdomains
              Strict-Transport-Security "max-age=31536000; includeSubDomains"

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
    # Use dbus-broker
    dbus.implementation = "broker";
    dnsmasq = {
      enable = true;
      # Don't change /etc/resolv.conf
      resolveLocalQueries = false;
      settings = {
        # Allow zone transfers from localhost
        # Dnsdist forwards zone transfers from other local sources
        auth-peer = "127.0.0.1,::1";

        # Be authoritative for queries on localhost with the SOA mname (master server) set to local.zandoodle.me.uk
        auth-server = "local.zandoodle.me.uk,192.168.1.201,::1,127.0.0.1";
        # Be authoritative for home.arpa and the associated rDNS zones.
        auth-zone = "home.arpa,192.168.0.0/16,fd00::/8";
        # Bind to configured interfaces as they appear
        bind-dynamic = true;
        # Respect any DHCP lease (Allows clients to change DHCP server after T2 rather than lease expirey)
        dhcp-authoritative = true;

        # Generate hostnames for hosts which don't provide one
        dhcp-generate-names = true;

        # Add hostnames for known hosts
        dhcp-host = [
          "52:54:00:12:34:56,web-vm,192.168.2.2,infinite"
        ];

        # Set the router, ntp server and DNS server addresses.
        dhcp-option = [
          "tag:guest,option:router,192.168.5.1"
          "tag:guest,option:ntp-server,192.168.5.1"
          "tag:guest,option:dns-server,192.168.5.201"
          "tag:shadow,option:router,192.168.10.1"
          "tag:shadow,option:dns-server,192.168.10.1"
          "tag:web-vm,option:router,192.168.2.1"
          "tag:web-vm,option:dns-server,192.168.2.1"
        ];
        # Enable DHCP and allocate from a suitable IP address range
        dhcp-range = [
          "set:guest,192.168.5.2,192.168.5.199,10m"
          "set:shadow,192.168.10.2,192.168.10.199,10m"
          "set:shadow,fd09:a389:7c1e:4::,fd09:a389:7c1e:4:ffff:ffff:ffff:ffff,64,10m"
          "set:web-vm,192.168.2.2,static"
        ];
        # Enable DHCP rapid commit (allows for a two message DHCP exchange)
        dhcp-rapid-commit = true;

        # Set the search domain for unqualified names
        domain = "home.arpa";

        # Add host records for the home router
        host-record = [
          "vodafone.home.arpa,192.168.1.1"
          "vodafone-guest.home.arpa,192.168.5.1"
        ];

        # Enable DHCP operation on C-VLAN 10, S-VLAN 20 and the web-vm TAP interface
        interface = [
          "guest"
          "2-shadow-2-lan"
          "web-vm"
        ];

        # Add a DNS entry for ourselves
        interface-name = [
          "orion-guest.home.arpa,guest"
          "orion-bridge.home.arpa,bridge"
          "orion-shadow.home.arpa,shadow"
        ];

        # Operate on port 56
        port = 56;

        # Add a placeholder record
        txt-record = "max.home.arpa,placeholder";
      };
    };
    knot = {
      enable = true;

      # Add shared caddy TSIG credentials
      keyFiles = [ "/run/credentials/knot.service/caddy" ];
      settings = {
        acl = [
          # Allow caddy to modify TXT records in _acme-challenge domains
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
          # Allow a zone transfer from local devices
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
            # Add a DNSSEC policy with a short rrsig lifetime and DS verfiication using unbound
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
          # Set an identity for id.server queries
          identity = "dns.zandoodle.me.uk";

          # Listen on all IPv4 and IPv6 addresses
          listen = ["0.0.0.0@54" "::@54"];

          # Set an identity for NSID
          nsid = "dns.zandoodle.me.uk";

          # Allow TCP Fast Open
          tcp-fastopen = true;

          # Open multiple TCP sockets
          tcp-reuseport = true;
        };
        submission = [
          {
            # Check DS submittion using unbound
            id = "unbound";
            parent = "unbound";
          }
        ];
        template = [
          {
            id = "default";
            # Add DNS cookies and rate limiting
            global-module = ["mod-cookies" "mod-rrl"];
          }
        ];
        zone = [
          {
            # Add a domain for DNSSEC testing
            acl = [ "transfer" ];
            domain = "bogus.zandoodle.me.uk";
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          }
          {
            # Add a domain for DNSSEC testing
            acl = [ "transfer" ];
            domain = "bogus-exists.zandoodle.me.uk";
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            # Don't modify the zonefile
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
      settings = {
        # Disable password based authentication
        KbdInteractiveAuthentication = false;
        PasswordAuthentication = false;
      };
    };
    # Disable systemd-resolved
    resolved.enable = false;
    unbound = {
      enable = true;
      localControlSocketPath = "/run/unbound/unbound.ctl";
      # Don't modify /etc/resolv.conf
      resolveLocalQueries = false;
      settings = {
        auth-zone = {
          fallback-enabled = true;
          for-downstream = false;
          for-upstream = true;
          name = ".";
          primary = [
            "199.9.14.201"         # b.root-servers.net
            "192.33.4.12"          # c.root-servers.net
            "199.7.91.13"          # d.root-servers.net
            "192.5.5.241"          # f.root-servers.net
            "192.112.36.4"         # g.root-servers.net
            "193.0.14.129"         # k.root-servers.net
            "192.0.47.132"         # xfr.cjr.dns.icann.org
            "192.0.32.132"         # xfr.lax.dns.icann.org
            "2001:500:200::b"      # b.root-servers.net
            "2001:500:2::c"        # c.root-servers.net
            "2001:500:2d::d"       # d.root-servers.net
            "2001:500:2f::f"       # f.root-servers.net
            "2001:500:12::d0d"     # g.root-servers.net
            "2001:7fd::1"          # k.root-servers.net
            "2620:0:2830:202::132" # xfr.cjr.dns.icann.org
            "2620:0:2d0:202::132"  # xfr.lax.dns.icann.org
          ];
          zonefile = "/var/lib/unbound/root.zone";
          zonemd-check = true;
          zonemd-reject-absence = true;
        };
        server = {
          # Allow queries from local devices
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
          # Allow querying localhost
          do-not-query-localhost = false;

          # Assume these domains are insecure and don't request DS records to prove it
          domain-insecure = [
            "broadband"
            "home.arpa"
            "168.192.in-addr.arpa."
            "d.f.ip6.arpa"
          ];

          # Enable Extended DNS Errors
          ede = true;
          ede-serve-expired = true;

          fast-server-permil = 900;

          # Reply to queries from the same address the query was sent to
          interface-automatic = true;

          # Disable local zones for special domains
          local-zone = [
            "home.arpa. nodefault"
            "168.192.in-addr.arpa. nodefault"
            "d.f.ip6.arpa. nodefault"
          ];

          log-servfail = true;

          # Set the nsid
          nsid = "ascii_recursive.dns.zandoodle.me.uk";

          # Use all cores
          num-threads = 12;
          port = 55;

          prefetch = true;

          prefetch-key = true;

          # Don't allow these addresses in a response by default
          private-address = [
            "10.0.0.0/8"
            "100.64.0.0/10"
            # "127.0.0.0/8"
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

          # Allow these domains respond with private addresses
          private-domain = [
            "compsoc-dev.com"
            "zandoodle.me.uk"
            "broadband"
            "home.arpa"

            # Returns localhost to connect with a local app
            "authenticatorlocalprod.com"
          ];

          # Serve expired records if a new answer can't be found
          serve-expired = true;

          # Report validator failures
          val-log-level = 2;
        };
        stub-zone = [
          {
            # Query knot for zandoodle.me.uk
            name = "zandoodle.me.uk";
            stub-addr = "127.0.0.1@54";
            stub-no-cache = true;
          }
          {
            # Query knot for compsoc-dev.com
            name = "compsoc-dev.com";
            stub-addr = "127.0.0.1@54";
            stub-no-cache = true;
          }
          {
            # Query the home router for broadband
            name = "broadband";
            stub-addr = "192.168.1.1";
            stub-no-cache = true;
          }
          {
            # Query dnsmasq for home.arpa
            name = "home.arpa";
            stub-addr = "127.0.0.1@56";
            stub-no-cache = true;
          }
          {
            # Query dnsmasq for 168.192.in-addr.arpa (192.168.0.0/16)
            name = "168.192.in-addr.arpa";
            stub-addr = "127.0.0.1@56";
            stub-no-cache = true;
          }
          {
            # Query dnsmasq for d.f.ip6.arpa (fd00::/8)
            name = "d.f.ip6.arpa";
            stub-addr = "127.0.0.1@56";
            stub-no-cache = true;
          }
        ];
      };
    };
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
    stateVersion = "24.11";
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
          bridgeConfig.STP = true;
          netdevConfig = {
            Kind = "bridge";
            Name = "bridge";
          };
        };

        # Configure an interface to manage C-VLAN 10 (guest Wi-Fi)
        "10-guest" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "guest";
          };
          vlanConfig = {
            Id = 10;
          };
        };

        # Configure a network for tesing purposes
        "10-experimental" = {
          extraConfig = ''
            [VLAN]
            Id=10
            Protocol=802.1ad
          '';
          netdevConfig = {
            Kind = "vlan";
            Name = "experimental";
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

        # Configure an S-VLAN based overlay network
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
          ipv6SendRAConfig = {
            # Don't advertise ourselves as a router to the internet
            RouterLifetimeSec = 0;
          };
          linkConfig = {
            AllMulticast = true;
            RequiredForOnline = false;
          };
          name = "bridge";
          networkConfig = {
            IPv6AcceptRA = true;
            IPv6PrivacyExtensions = "kernel";
            IPv6SendRA = true;
          };
          ipv6Prefixes = [
            {
              # Advertise fd09:a389:7c1e:5::/64 as the network address and allow
              # devices to allocate an address
              Assign = true;
              Prefix = "fd09:a389:7c1e:5::/64";
            }
          ];
          routes = [
            {
              # Add a static route to the router
              Gateway = "192.168.1.1";
              PreferredSource = "192.168.1.201";
            }
          ];
          # Create VLANs and bind them to this interface
          vlan = [ "2-shadow-2-lan" "experimental" "guest" ];
        };
        # configure the guest interface
        "10-guest" = {
          address = [ "192.168.5.201/24" ];

          # Don't wait for this interface to be configured
          linkConfig.RequiredForOnline = false;
          name = "guest";
          networkConfig.IPv6AcceptRA = false;
        };
        "10-enp1s0" = {
          bridge = [ "bridge" ];
          matchConfig = {
            Name = "enp1s0";
          };
          # address = [ "192.168.0.1/24" ];
          # ipv6Prefixes = [
          #   {
          #     Assign = true;
          #     Prefix = "fd09:a389:7c1e:7::/64";
          #   }
          # ];
          # ipv6SendRAConfig = {
          #   DNS = "_link_local";
          #   EmitDNS = true;
          #   Managed = true;
          #   RouterLifetimeSec = 0;
          # };
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
          name = "enp49s0";
        };

        # Configure S-VLAN 10 (unused)
        "10-experimental" = {
          address = [ "192.168.11.1/24" ];
          ipv6Prefixes = [
            {
              Assign = true;
              Prefix = "fd09:a389:7c1e:6::/64";
            }
          ];
          ipv6SendRAConfig = {
            Managed = true;
            RouterLifetimeSec = 0;
          };
          name = "experimental";
          networkConfig.IPv6SendRA = true;
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

        # Configure S-VLAN 20
        "10-2-shadow-2-lan" = {
          address = [ "fd09:a389:7c1e:4::1/64" "192.168.10.1/24" ];
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
            Managed = true;
            RouterLifetimeSec = 0;
          };

          # Advertise NAT64 prefixes
          ipv6PREF64Prefixes = [
            {
              Prefix = "fd09:a389:7c1e:3::/64";
            }
          ];
          linkConfig.RequiredForOnline = false;
          matchConfig.Name = "2-shadow-2-lan";
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
    packages = [
      # Add the dnsdist service
      pkgs-unstable.${config.nixpkgs.system}.dnsdist
    ];
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
      dnsdist = {
        serviceConfig = {
          # Override the dnsdist service to use /etc/dnsdist/dnsdist.conf
          ExecStart = [
            ""
            "${lib.getExe pkgs-unstable.${config.nixpkgs.system}.dnsdist} --supervised --disable-syslog --config /etc/dnsdist/dnsdist.conf"
          ];
          ExecStartPre = [
            ""
            "${lib.getExe pkgs-unstable.${config.nixpkgs.system}.dnsdist} --check-config --config /etc/dnsdist/dnsdist.conf"
          ];

          # Add the dnsdist cgroup to the services table
          NFTSet = "cgroup:inet:services:dnsdist";

          # Run as a dedicated user
          User = "dnsdist";
          Group = "dnsdist";
        };

        # Restart dnsdist when the config changes
        restartTriggers = [ config.environment.etc."dnsdist/dnsdist.conf".source ];

        # Restart dnsdist immediatly
        startLimitIntervalSec = 0;

        # Start dnsdist on boot
        wantedBy = [ "multi-user.target" ];
      };

      # Add the dnsmasq cgroup to the services table
      dnsmasq.serviceConfig.NFTSet = "cgroup:inet:services:dnsmasq";

      # Generate a TSIG key for caddy
      gen-tsig = {
        # Generate the TSIG key before knot or caddy starts
        before = [ "knot.service" "caddy.service" ];
        requiredBy = [ "knot.service" "caddy.service" ];
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
          # Generate a TSIG key
          ${lib.getExe' pkgs.knot-dns "keymgr"} -t caddy >/run/keymgr/caddy
          for attr in id algorithm secret; do
            # Split the elements of the key into seperate files for caddy
            ${lib.getExe pkgs.yq} -r .key.[]."$attr" </run/keymgr/caddy >/run/keymgr/caddy-"$attr"
          done
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

          # Get the IP address for enp49s0
          ${lib.getExe' pkgs.iproute2 "ip"} -json address show dev bridge | ${lib.getExe pkgs.jq} -r \
            '.[].addr_info.[]
              | if .family == "inet" then
                "@ A " + .local
              elif (.family == "inet6") and (.scope != "link") then
                "@ AAAA " + .local
              else
                empty
              end' >/run/ddns/local-zonefile

          # Check the zonefile is valid
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/local-zonefile

          # Get the IP address for guest
          ${lib.getExe' pkgs.iproute2 "ip"} -json address show dev guest | ${lib.getExe pkgs.jq} -r \
            '.[].addr_info.[]
              | if .family == "inet" then
                "@ A " + .local
              elif (.family == "inet6") and (.scope != "link") then
                "@ AAAA " + .local
              else
                empty
              end' >/run/ddns/local-guest-zonefile

          # Check the zonefile is valid
          ${lib.getExe' pkgs.ldns.examples "ldns-read-zone"} -c /run/ddns/local-guest-zonefile

          # Record differences in the public IP address
          if ! ${lib.getExe' pkgs.diffutils "diff"} /run/ddns/zonefile /var/lib/ddns/zonefile; then
            cp --backup=numbered /run/ddns/zonefile "/var/lib/ddns/zonefile-$(date --iso-8601=seconds)"
          fi

          # Move the verified data from /run/ddns to /var/lib/ddns
          ${lib.getExe' pkgs.coreutils "mv"} -f /run/ddns/IPv4-address \
            /run/ddns/zonefile /run/ddns/local-zonefile /run/ddns/local-guest-zonefile /var/lib/ddns/
        '';
        unitConfig.StartLimitIntervalSec = "20m";

        # Start on boot
        wantedBy = ["multi-user.target"];
      };
      knot.serviceConfig = {
        # Get the TSIG credentials for caddy
        LoadCredential = "caddy:/run/keymgr/caddy";

        # Allow knot to open as many files as it wants
        LimitNOFILE = "infinity";

        # Add the knot cgroup to the services firewall table
        NFTSet = "cgroup:inet:services:knot";
      };

      # Reload knot after a zone change
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
