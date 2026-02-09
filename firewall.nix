{ pkgs, ... }: {
  networking = {
    firewall = {
      # Allow DNS, HTTP and HTTPS
      allowedUDPPorts = [ 53 54 88 443 464 41641 ];
      allowedTCPPorts = [ 25 53 54 80 88 389 443 464 749 853 ];
      extraForwardRules = ''
        iifname {plat, guest, "shadow-lan", "bridge", "tailscale0"} oifname {plat, guest, "shadow-lan", "bridge"} accept
      '';
      extraInputRules = ''
        # Allow local devices to reach the local DNS servers (unbound and dnsmasq)
        meta l4proto {udp, tcp} th dport {55, 56, 5353} ip saddr @local_ip accept
        meta l4proto {udp, tcp} th dport {55, 56, 5353} ip6 saddr @local_ip6 accept
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
    nftables = {
      # Disable checking the ruleset using lkl as cgroups are not enabled in lkl
      checkRuleset = false;
      enable = true;

      # Don't flush the entire ruleset and instead delete specific tables
      flushRuleset = false;
      ruleset = ''
        include "/etc/no_mdns.nft"
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

          set slapd {
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

          set no_mdns {
            type ether_addr; flags constant;
          }

          chain local_input {
            # Allow SSH from local devices
            tcp dport 22 socket cgroupv2 level 2 @sshd accept

            meta l4proto {udp, tcp} th dport 55 socket cgroupv2 level 2 @unbound accept
            meta l4proto {udp, tcp} th dport 56 socket cgroupv2 level 2 @dnsmasq accept
            meta l4proto {udp, tcp} th dport 5353 ether saddr != @no_mdns socket cgroupv2 level 2 @avahi accept

            # Allow Kerberos
            meta l4proto {udp, tcp} th dport 88 socket cgroupv2 level 4 @kdc accept
            meta l4proto {udp, tcp} th dport {464, 749} socket cgroupv2 level 4 @kadmin accept

            # Allow LDAP
            meta l4proto tcp th dport 389 socket cgroupv2 level 2 @slapd accept

            iifname { "bridge", lo, tailscale0 } tcp dport { 465, 587, 993 } socket cgroupv2 level 2 @maddy accept

            tcp dport { 22, 55, 56, 88, 389, 464, 465, 587, 749, 993 } reject
            udp dport { 55, 56, 88, 464, 749 } reject
          }

          chain input {
            type filter hook input priority filter + 10; policy drop;
            ct state vmap { invalid : drop, established : accept, related : accept }
            ip saddr == @local_ip jump local_input
            ip6 saddr == @local_ip6 jump local_input

            # Allow DNS handled by dnsdist, knot, unbound and dnsmasq
            meta l4proto {udp, tcp} th dport 53 socket cgroupv2 level 2 @dnsdist accept
            meta l4proto {udp, tcp} th dport 54 socket cgroupv2 level 2 @knot accept
            iifname lo tcp dport 8080 socket cgroupv2 level 2 @unbound accept

            # Allow HTTP and HTTPS handled by caddy
            tcp dport { 80, 443, 853 } socket cgroupv2 level 2 @caddy accept
            udp dport 443 socket cgroupv2 level 2 @caddy accept

            # Allow DHCP handled by dnsmasq
            udp dport 67 iifname { shadow-lan, guest, web-vm } socket cgroupv2 level 2 @dnsmasq accept
            udp dport 547 iifname { shadow-lan, guest, "bridge" } socket cgroupv2 level 2 @dnsmasq accept

            iifname lo tcp dport 11434 socket cgroupv2 level 2 @ollama_socket accept

            udp dport 41641 socket cgroupv2 level 2 @tailscaled accept

            tcp dport 25 socket cgroupv2 level 2 @maddy accept

            icmpv6 type != { nd-redirect, 139 } accept
            ip6 daddr fe80::/64 udp dport 546 socket cgroupv2 level 2 @systemd_networkd accept
            icmp type echo-request accept comment "allow ping"

            tcp dport {25, 53, 54, 80, 443, 853} reject
            udp dport {53, 54, 67, 443, 547, 41641} reject
          }
        }
      '';
      extraDeletions = ''
        # Initialise services table so that the input chain can be flushed
        table inet services {
          chain local_input {
          }
          chain input {
          }
        }
        flush chain inet services input
        delete chain inet services input
        flush chain inet services local_input
        delete chain inet services local_input
        destroy set inet services local_ip
        destroy set inet services local_ip6
        destroy set inet services no_mdns
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
  };
  systemd = {
    services = {
      avahi-daemon = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:avahi";
        wants = [ "nftables.service" ];
      };
      caddy = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:caddy";
        wants = [ "nftables.service" ];
      };
      dnsdist = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:dnsdist";
        wants = [ "nftables.service" ];
      };
      dnsmasq = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:dnsmasq";
        wants = [ "nftables.service" ];
      };
      knot = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:knot";
        wants = [ "nftables.service" ];
      };
      maddy = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:maddy";
        wants = [ "nftables.service" ];
      };
      nftables = {
        confinement = {
          enable = true;
          packages = [ pkgs.coreutils ];
        };
        serviceConfig = {
          BindReadOnlyPaths = [ "/etc/no_mdns.nft" ];
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
      slapd = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:slapd";
        wants = [ "nftables.service" ];
      };
      sshd = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:sshd";
        wants = [ "nftables.service" ];
      };
      systemd-networkd = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:systemd_networkd";
        wants = [ "nftables.service" ];
      };
      tailscaled = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:tailscaled";
        wants = [ "nftables.service" ];
      };
      unbound = {
        after = [ "nftables.service" ];
        serviceConfig.NFTSet = "cgroup:inet:services:unbound";
        wants = [ "nftables.service" ];
      };
    };
    sockets = {
      kadmind = {
        after = [ "nftables.service" ];
        socketConfig.NFTSet = "cgroup:inet:services:kadmin";
        wants = [ "nftables.service" ];
      };
      kdc = {
        after = [ "nftables.service" ];
        socketConfig.NFTSet = "cgroup:inet:services:kdc";
        wants = [ "nftables.service" ];
      };
      ollama-proxy = {
        after = [ "nftables.service" ];
        socketConfig.NFTSet = "cgroup:inet:services:ollama_socket";
        wants = [ "nftables.service" ];
      };
    };
  };
}
