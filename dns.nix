{ config, lib, pkgs, pkgs-unstable, ... }:
{
  environment.etc = {
    "dnsdist/dnsdist.conf".text = ''
      -- listen on all IPv4 and IPv6 addresses
      addLocal("0.0.0.0:53")
      addLocal("[::]:53")

      local private_addresses = newNMG()
      private_addresses:addMask("127.0.0.0/8")
      private_addresses:addMask("10.0.0.0/8")
      private_addresses:addMask("100.64.0.0/10")
      private_addresses:addMask("169.254.0.0/16")
      private_addresses:addMask("192.168.0.0/16")
      private_addresses:addMask("172.16.0.0/12")
      private_addresses:addMask("::1/128")
      private_addresses:addMask("fc00::/7")
      private_addresses:addMask("fe80::/10")

      local apex_domains = newDNSNameSet()
      apex_domains:add(newDNSName("zandoodle.me.uk"))
      apex_domains:add(newDNSName("compsoc-dev.com"))

      -- Make sure the query is for a public zone
      local public_zone_rule = AndRule({
        QNameSuffixRule({"zandoodle.me.uk", "compsoc-dev.com"}),
        NotRule(AndRule({
          QNameSetRule(apex_domains),
          QTypeRule(DNSQType.DS),
        })),
      })

      -- Add local DNS servers
      newServer({address = "[::1]:54", name = "knot-dns", pool = "auth", healthCheckMode = "lazy"})
      newServer({address = "[::1]:55", name = "unbound", pool = "iterative", healthCheckMode = "lazy"})
      newServer({address = "[::1]:56", name = "dnsmasq", pool = "dnsmasq", healthCheckMode = "lazy"})

      -- Allow connections from all IP addresses
      setACL({"0.0.0.0/0", "::/0"})

      -- Forward recursive queries to the recursive resolver (unbound)
      addAction(AndRule({RDRule(), NetmaskGroupRule(private_addresses)}), PoolAction("iterative"))

      -- Provide some rate limiting
      addAction(
        AndRule({
          TCPRule(false),
          OrRule({
            QClassRule(DNSClass.CHAOS),
            MaxQPSIPRule(5),
          }),
        }),
        TCAction())

      -- Allow Hetzner to transfer from this server
      local axfr_addresses = newNMG()
      axfr_addresses:addNMG(private_addresses)
      axfr_addresses:addMask("2a01:4f8:0:a101::a:1/128")
      axfr_addresses:addMask("2a01:4f8:0:1::5ddc:2/128")
      axfr_addresses:addMask("2001:67c:192c::add:a3/128")

      addAction(
        AndRule({
          OrRule({QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}),
          NotRule(NetmaskGroupRule(axfr_addresses)),
        }),
        DropAction())

      -- Forward all remaining queries to the authoritative DNS server (knot)
      addAction(
        OrRule({
          NetmaskGroupRule(private_addresses),
          public_zone_rule,
          QClassRule(DNSClass.CHAOS),
        }),
        PoolAction("auth"))
    '';
    "dnsmasq.conf".source = config.services.dnsmasq.configFile;
    "knot/acme-challenge.zandoodle.me.uk.zone".text = ''
      @ soa dns.zandoodle.me.uk. hostmaster.zandoodle.me.uk. 0 14400 3600 604800 86400
      @ ns dns.zandoodle.me.uk.
    '';
    "knot/bogus.zandoodle.me.uk.zone".text = ''
      ; A zone for testing DNSSEC support.
      ; This zone is bogus.
      $TTL 0
      @ soa dns.zandoodle.me.uk. hostmaster.zandoodle.me.uk. 0 14400 3600 604800 86400

      ; DANE testing
      _tcp dname _tcp.zandoodle.me.uk.
      _tls dname _tls.zandoodle.me.uk.

      ; Setup SPF for this domain
      @ txt "v=spf1 redirect=_spf.zandoodle.me.uk"
      @ mx 10 mail

      ; Advertise our public IP address as the IP address for this domain
      $INCLUDE /var/lib/ddns/zonefile

      @ NS dns.zandoodle.me.uk.
    '';
    "knot/compsoc-dev.com.zone".text = ''
      $TTL 600
      @ soa dns.zandoodle.me.uk. hostmaster 0 14400 3600 604800 86400

      ; Advertise DANE
      _tcp dname _tcp.zandoodle.me.uk.
      _tls dname _tls.zandoodle.me.uk.

      ; Setup mail for this domain
      @ mx 10 mail.zandoodle.me.uk.
      @ txt "v=spf1 redirect=_spf.zandoodle.me.uk"
      _dmarc cname _dmarc.zandoodle.me.uk.
      _mta-sts cname _mta-sts.zandoodle.me.uk.
      _mta-sts.mail cname _mta-sts.zandoodle.me.uk.
      mail mx 10 mail.zandoodle.me.uk.
      mail txt "v=spf1 mx -all"
      _tls.mail dname _tls.zandoodle.me.uk.
      mta-sts.mail cname @
      _acme-challenge.mta-sts.mail cname _acme-challenge.zandoodle.me.uk.

      ; Advertise our public IP address as the IP address for compsoc-dev.com
      $INCLUDE /var/lib/ddns/zonefile
      mta-sts cname @
      _acme-challenge.mta-sts cname _acme-challenge.zandoodle.me.uk.
      ollama cname local-tailscale.zandoodle.me.uk.
      _acme-challenge.ollama cname _acme-challenge.zandoodle.me.uk.
      _tcp.ollama dname _tcp.zandoodle.me.uk.

      ; Setup certificate authority restrictions
      @ CAA 0 issuemail ";"
      @ CAA 0 issuevmc ";"
      @ CAA 0 issuewild ";"
      ; Only Let's Encrypt can issue for this domain and only using the dns-01 validation method
      @ CAA 128 issue "letsencrypt.org;validationmethods=dns-01"

      ; Advertise HTTP/2 and HTTP/3 support
      @ HTTPS 1 . alpn=h3,h2

      ; Advertise the authoritative nameserver
      @ ns dns.zandoodle.me.uk.
      ; Advertise Hetzner secondary nameservers
      @ ns ns1.first-ns.de.
      @ ns robotns2.second-ns.de.
      @ ns robotns3.second-ns.com.

      default._domainkey TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs9i5JfSz0iOz0L5xG9OwO8N9bdhY+YT+Hq3AVCupqZmp487NTem0yoPEgfZDqVxGaTFVdCxAMhHHvv08jo6U5Cmubumo8HHGzwvYJux9CCWcbUFlr3994Avs04O5sDSXmeDDuG9rGZmepy0r+Gly0brAKEv6UxM2l1HnBB2qabkCzYUamc9TyH8BUM9PIj3RWVEO/FHo8XjYxwrMLd22inHQ8wAORc3ERXqEEe/XgaxnWmD4ledoqRF8imcmqClXN+2f7+WvsJo+/ovi5Oh7+8WfLyx9KVWwjWHPgd6a9Dm/ArSjiZbzR+DpynQZi+AvUXIxBpeQXlvofl0W+479pwIDAQAB"
      default._domainkey.mail txt "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+wMyRqY5sX/bHyuyYlSHM3N0tEqoCV6zQnSjMwCrxoETQsBx6ceXvFmEW1JCE9rp2l+DVDFk9IUVhvMUqHfC+NBKDojqX7PX4gNHrP+E6wkmPRuNzff07dHMSRat1pugpleP9oJgffJBjpGh/YpROsDbpOhlggd5gQjkgP2hH6JsrEwPtdRA/VBqGi6fonSpP9aWB19GVEKAx1xnpaZy991mzcpPSGhXXlOLXM6tgDthBEk0KCcJ3nKoIzbiDRc9oWRlyBxfOND2DYiDMVV02D2ykswCGb5GKhJ4Dy6KbFr9jbUo4h8zdN765P52Phd+tddDOVCbA9xyUI4rTZmkwIDAQAB"

      flag-0be5c4b29b type65534 \# 0
      flag-0be5c4b29b txt "v=spf1 -all"

      ; Add google site verification
      @ TXT "google-site-verification=oZJUabY5f9TzTiPw8Ml-k8GrRILLRbITIEF8eamsLY4"

      _acme-challenge cname _acme-challenge.zandoodle.me.uk.
    '';
    "knot/home.arpa.zone".text = ''
      $TTL 600
      @ soa local.zandoodle.me.uk. hostmaster.zandoodle.me.uk. 0 1200 180 1209600 600
      @ ns local.zandoodle.me.uk.
      max ns workstation.zandoodle.me.uk.
      ax3000 a 192.168.1.202
      orion ns local.zandoodle.me.uk.
      vodafone a 192.168.1.1
      vodafone-guest a 192.168.5.1
    '';
    "knot/letsencrypt.zone.include".source =
      pkgs.callPackage ./gen-TLSA.nix {
        names = [ "ISRG_Root_X1" "ISRG_Root_X2" ];
      };
    "knot/letsencrypt-dane.zone.include".source =
      pkgs.callPackage ./gen-TLSA.nix {
        names = [
          "e7-cross.der"
          "e7.der"
          "e8-cross.der"
          "e8.der"
          "e9-cross.der"
          "e9.der"
          "int-ye1.der"
          "int-ye2.der"
          "int-ye3.der"
          "int-yr1.der"
          "int-yr2.der"
          "int-yr3.der"
          "r12.der"
          "r13.der"
          "r14.der"
        ];
        bundle = ./intermediates;
        bundle_subdir = ".";
        tlsa_usage = 2;
        tlsa_selector = 0;
        tlsa_matching = 1;
      };
    "knot/no-email.zone.include".text = ''
      ; Deny sending or receiving emails
      @ TXT "v=spf1 -all"
      @ MX 0 .
    '';
    "knot/rDNS.zone".text = ''
      $TTL 600
      @ soa local.zandoodle.me.uk. hostmaster.zandoodle.me.uk. 0 1200 180 1209600 600
      @ ns local.zandoodle.me.uk.
    '';
    "knot/zandoodle.me.uk.zone".text = ''
      $TTL 600
      @ SOA dns hostmaster 0 14400 3600 604800 86400

      ; Setup DANE for this domain
      $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.zandoodle.me.uk.
      $INCLUDE /etc/knot/letsencrypt-dane.zone.include _25._tcp.mail.zandoodle.me.uk.

      _tcp.local dname _tcp

      ; Setup SPF and DMARC for this domain
      @ txt "v=spf1 redirect=_spf.zandoodle.me.uk"
      _dmarc txt "v=DMARC1;p=reject;aspf=s;adkim=s;fo=d;rua=mailto:dmarc-reports@zandoodle.me.uk;ruf=mailto:dmarc-reports@zandoodle.me.uk"
      compsoc-dev.com._report._dmarc txt "v=DMARC1;"
      mail txt "v=spf1 a -all"

      ; Setup mail exchanges for this domain
      @ mx 10 mail
      mail mx 10 mail

      ; Setup MTA-STS for this domain
      _mta-sts txt "v=STSv1; id=1"
      _mta-sts.mail cname _mta-sts

      ; Setup TLSRPT
      _tls.mail dname _tls
      _smtp._tls txt "v=TLSRPTv1;rua=mailto:tlsrpt@zandoodle.me.uk"

      ; Advertise imaps and submissions
      _imaps._tcp SRV 0 10 993 imap
      _submissions._tcp SRV 0 10 465 smtp
      _submission._tcp SRV 0 10 587 smtp
      _kerberos uri 10 1 krb5srv:m:udp:local.zandoodle.me.uk
      _kerberos uri 20 1 krb5srv:m:tcp:local.zandoodle.me.uk
      _kerberos txt ZANDOODLE.ME.UK
      _kerberos._udp srv 0 10 88 local
      _kerberos._tcp srv 0 10 88 local

      _acme-challenge ns dns

      _acme-challenge.mail ns dns

      $INCLUDE /etc/knot/no-email.zone.include dns.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local-guest.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local-shadow.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local-tailscale.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include workstation.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include pc.zandoodle.me.uk.
      _spf txt "v=spf1 ?a:mail.zandoodle.me.uk -all"

      ; Setup DKIM for this domain
      default._domainkey TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCuGmFxA7aupe8x7tmSolntpa5qBxyQnGkgsfjyjD57doP55a57KXTxEo6t7buBpua/W6dktcw2zpLp9338yg1wA/9RJwhZclzrH5Kv4gNbMHHvhBbygnoJqbrwFH8+VDNG4NKUl5WKFRiITJXd8Y0xqpPhFwfmd2nITjc8wleGv4eQXmB5ytP8Nj2fE6pd4fGpF7sydnOo5BTBSeb0QtmgbQcReQ05CqwMGEAyKOQFnKMzEAOEtvyXUFyG7hFt4ZsngpRGDM/1d4rI/Kh7oCFfzuhR+ENhZkLqYz9xZ0QZ3GWVon7mXfiVvJL5GBfb9cwLjAGp5QhgN2El2yc/3/QIDAQAB"
      default._domainkey.mail txt "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1VJx8wBBOAQWOk+6i7MuJel5lV7glADvBG3g+UcW5wn/mbGJdsyGpoI33694ZSBth4y3OHeVP11ydIznHY0fuBviAKVyLQZN94j5Nw4rH4xZXGhHXxUqBcMuHKHrj5jp2cd/rgtCX18W8YkSYEU6yZpbjle8NoMFRK5OFuLNeni7jOtPGE3P7JyfzY0umkiLemVn5w/HREf0i6un7DJ/iq3OG3Pd3MWxbcIYwRf3+zpRybjOTwgBhfHXNysJ8QZiz5fg3wCYzEYy2AyXbhF2PZNqZrId3oaFiGGhX13ffUSVGdR7VS9zwmIQoEG+jrOitMocywf8X1HIeB5m8zfHWwIDAQAB"

      ; Advertise IP addresses for this domain
      $INCLUDE /var/lib/ddns/local-zonefile local.zandoodle.me.uk.
      $INCLUDE /var/lib/ddns/local-guest-zonefile local-guest.zandoodle.me.uk.
      $INCLUDE /var/lib/ddns/local-tailscale-zonefile local-tailscale.zandoodle.me.uk.
      $INCLUDE /var/lib/ddns/zonefile
      ; NS and MX targets musn't be an alias
      $INCLUDE /var/lib/ddns/zonefile-ipv6-only dns.zandoodle.me.uk.
      $INCLUDE /var/lib/ddns/zonefile mail.zandoodle.me.uk.

      imap cname local-tailscale
      _acme-challenge.imap cname _acme-challenge.mail
      smtp cname local-tailscale
      _acme-challenge.smtp cname _acme-challenge.mail
      smtp-local cname local
      _acme-challenge.smtp-local cname _acme-challenge.mail
      cardgames cname @
      _acme-challenge.cardgames cname _acme-challenge
      mta-sts cname @
      _acme-challenge.mta-sts cname _acme-challenge
      mta-sts.mail cname @
      _acme-challenge.mta-sts.mail cname _acme-challenge
      recursive.dns cname local
      _acme-challenge.recursive.dns cname _acme-challenge
      wss.cardgames cname @
      _acme-challenge.wss.cardgames cname _acme-challenge
      _acme-challenge.local cname _acme-challenge

      ; Setup certificate authority restrictions for this domain
      @ CAA 0 issuemail ";"
      @ CAA 0 issuevmc ";"
      @ CAA 0 issuewild ";"
      ; Only Let's Encrypt can issue for this domain and only using the dns-01 validation method
      @ CAA 128 issue "letsencrypt.org;validationmethods=dns-01"

      ; Advertise HTTP/2 and HTTP/3 support for zandoodle.me.uk
      @ HTTPS 1 . alpn=h3,h2

      ; Advertise the primary DNS server
      @ ns dns
      ; Advertise Hetzner secondary nameservers
      @ ns ns1.first-ns.de.
      @ ns robotns2.second-ns.de.
      @ ns robotns3.second-ns.com.

      ; Setup an extant domain for DNSSEC testing
      bogus-exists TYPE65534 \# 0

      dot-check\. txt dot\ check
      dot-check\. txt "v=spf1 -all"

      ; Advertise HTTP/2 and HTTP/3 support for local.zandoodle.me.uk
      local HTTPS 1 . alpn=h3,h2

      ; Public SSH key fingerprints for local domains
      local IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
      local-guest IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local-guest IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
      local-shadow IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local-shadow IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
      local-tailscale IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local-tailscale IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81

      local-shadow A 192.168.4.1
      local-shadow AAAA fd09:a389:7c1e:1::1

      multi-string-check TXT string 1 string 2
      multi-string-check txt "v=spf1 -all"

      ; Check that null bytes within TXT records are handled correctly
      null-check TXT "\000"
      null-check txt "v=spf1 -all"

      ; Check that null bytes within domains are handled correctly
      null-domain-check\000 TXT "null domain check"

      ; Add a zero ttl record for testing DNS resolvers
      ttl-check 0 txt ttl\ check
      ttl-check 0 txt "v=spf1 -all"

      chromebook a 100.69.85.70
      chromebook aaaa fd7a:115c:a1e0::d401:5546
      chromebook sshfp 1 2 dc6283b6624010239844b07c3c6e4691233ceb4a46c86c36402cfcfe3a1eceda
      chromebook sshfp 4 2 522f2d5021c6d6250d99b77bea672fbfaac6c5b8a4ef6950d49267da9ecc11ee
      _kerberos.chromebook txt WORKSTATION.ZANDOODLE.ME.UK

      laptop a 100.68.198.4
      laptop aaaa fd7a:115c:a1e0::d601:c604
      laptop sshfp 1 2 74f8b963573c943f69119ed3383dcf34471acc5ac61e6136cc7daddce57e9dad
      laptop sshfp 4 2 af1162523e3f11a434bec1a78f6b8c5bf0b9f5c187391a08004afb8b5d7d8195
      _kerberos.laptop txt WORKSTATION.ZANDOODLE.ME.UK

      pc a 100.95.236.105
      pc aaaa fd7a:115c:a1e0::d2df:ec69
      pc sshfp 1 2 ea259e9d2d355d9506919e56ed0c35fbb0476501524f6349cf9f6ef6dbe19c50
      pc sshfp 4 2 7191d7ac7c0eaa18df828f22b4b948e2efc6281c3ca7aab5a78a5beef4b30d5b
      _kerberos.pc txt WORKSTATION.ZANDOODLE.ME.UK


      workstation a 100.91.224.22
      workstation aaaa fd7a:115c:a1e0:ab12:4843:cd96:625b:e016
      workstation caa 128 issue "letsencrypt.org;validationmethods=dns-01"
      workstation caa 0 issuemail ";"
      workstation caa 0 issuevmc ";"
      workstation IN SSHFP 1 2 bb26ac7d22088477cf1a3f701f702595025a569c7373306bbfb44d880202322f
      workstation IN SSHFP 4 2 7fa4a718df8a2c3fe600f3d9976d00ac825d56a1ca41b5b36026a279400642e8
      *.workstation cname workstation
      _acme-challenge.workstation ns dns
      _kerberos.workstation txt WORKSTATION.ZANDOODLE.ME.UK
      _kerberos.workstation uri 10 1 krb5srv:m:tcp:workstation.zandoodle.me.uk
      _kerberos._tcp.workstation srv 0 10 88 workstation
      _kerberos._udp.workstation srv 0 10 88 workstation

      ; Google stuff
      @ TXT "google-site-verification=ZDVckD_owTCKFzcbI9VqqGQOoNfd_8C0tKNqRVkiK8I"
    '';
    "resolv.conf".text = ''
      # Use the local DNS resolver
      nameserver ::1
      nameserver 127.0.0.1

      # Trust the AD (authentic data) flag and use EDNS(0)
      options trust-ad edns0
    '';
  };
  networking.nftables.tables.dns = {
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
        fib daddr . mark type local udp dport 53 redirect to :54 comment "Recursion not desired"
        fib daddr . mark type local tcp dport 53 ip saddr != @local_ip redirect to :54 comment "Tcp recursion not desired"
        fib daddr . mark type local tcp dport 53 ip6 saddr != @local_ip6 redirect to :54 comment "Tcp recursion not desired"
      }

      chain dns-rd-output {
        type nat hook output priority dstnat; policy accept;
        # Redirect recusive queries from ourself to unbound
        fib daddr . mark type local udp dport 53 @th,87,1 == 1 ip saddr @local_ip redirect to :55 comment "Recursion desired"
        fib daddr . mark type local udp dport 53 @th,87,1 == 1 ip6 saddr @local_ip6 redirect to :55 comment "Recursion desired"
        fib daddr . mark type local udp dport 53 redirect to :54 comment "Recursion not desired"
      }
    '';
  };
  services = {
    dbus.packages = [
      (pkgs.writeTextDir "share/dbus-1/system.d/dnsmasq-rootless.conf" ''
        <!DOCTYPE busconfig PUBLIC
         "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
         "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
        <busconfig>
                <policy user="dnsmasq">
                        <allow own="uk.org.thekelleys.dnsmasq"/>
                        <allow send_destination="uk.org.thekelleys.dnsmasq"/>
                </policy>
        </busconfig>
      '')
    ];
    dnsmasq = {
      enable = true;
      package = pkgs.dnsmasq.overrideAttrs (
        { patches ? [], ... }: {
          patches = patches ++ [ ./dnsmasq-ixfr.patch ];
        });
      # Don't change /etc/resolv.conf
      resolveLocalQueries = false;
      settings = {
        # Allow zone transfers from localhost
        # Dnsdist forwards zone transfers from other local sources
        auth-peer = "127.0.0.1,::1";

        # Be authoritative for queries on localhost with the SOA mname (master server) set to local.zandoodle.me.uk
        auth-server = "local.zandoodle.me.uk,192.168.1.201,::1,127.0.0.1";
        # Set the email address for the zone
        auth-soa = "0,hostmaster.zandoodle.me.uk";
        # Be authoritative for home.arpa and the associated rDNS zones.
        auth-zone = "orion.home.arpa,192.168.0.0/16,fd00::/8";
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
          "tag:has-routes,tag:guest,option:router,192.168.5.1"
          "tag:has-routes,tag:guest,option:static-route,192.168.1.0,192.168.5.201,192.168.4.0,192.168.5.201,192.168.6.0,192.168.5.201,192.168.8.0,192.168.5.201,192.168.9.0,192.168.5.201"
          "tag:guest,option:ntp-server,192.168.5.1"
          "tag:guest,option:dns-server,192.168.5.201"
          "tag:!has-routes,tag:guest,option:router,192.168.6.1"
          "tag:shadow,option:router,192.168.4.1"
          "tag:shadow,option:dns-server,192.168.4.1"
          "tag:shadow,option:static-route,192.168.1.0,192.168.4.1,192.168.5.0,192.168.4.1,192.168.6.0,192.168.4.1,192.168.8.0,192.168.4.1,192.168.9.0,192.168.4.1"
          "tag:web-vm,option:router,192.168.2.1"
          "tag:web-vm,option:dns-server,192.168.2.1"
          "option:domain-search,orion.home.arpa,home.arpa"
        ];
        dhcp-match = "set:has-routes,55,!";
        # Enable DHCP and allocate from a suitable IP address range
        dhcp-range = [
          "tag:has-routes,set:guest,192.168.5.2,192.168.5.199,10m"
          "tag:!has-routes,set:guest,192.168.6.2,192.168.6.199,10m"
          "set:guest,fd09:a389:7c1e:4::,fd09:a389:7c1e:4:ffff:ffff:ffff:ffff,64,10m"
          "set:shadow,192.168.4.2,192.168.4.199,10m"
          "set:shadow,fd09:a389:7c1e:1::,fd09:a389:7c1e:1:ffff:ffff:ffff:ffff,64,10m"
          "fd09:a389:7c1e:5::,fd09:a389:7c1e:5:ffff:ffff:ffff:ffff,64,10m"
          "set:web-vm,192.168.2.2,static"
        ];
        # Enable DHCP rapid commit (allows for a two message DHCP exchange)
        dhcp-rapid-commit = true;

        # Set the search domain for unqualified names
        domain = "orion.home.arpa";

        # Enable DHCP operation on C-VLAN 10, S-VLAN 20 and the web-vm TAP interface
        interface = [
          "bridge"
          "guest"
          "shadow-lan"
          "web-vm"
        ];

        # Add a DNS entry for ourselves
        interface-name = [
          "orion-guest.orion.home.arpa,guest"
          "orion-bridge.orion.home.arpa,bridge"
          "orion-shadow.orion.home.arpa,shadow-lan"
        ];

        no-hosts = true;

        # Operate on port 56
        port = 56;
      };
    };
    knot = {
      enable = true;

      # Add shared caddy TSIG credentials
      keyFiles = [
        "/run/credentials/knot.service/caddy"
        "/run/credentials/knot.service/knot-ds"
        "/run/credentials/knot.service/maddy"
        "/etc/knot/workstation.tsig"
      ];
      settings = {
        acl = {
          caddy-acme = {
            # Allow caddy to modify TXT records in _acme-challenge domains
            address = "::1";
            action = "update";
            key = "caddy";
            update-owner = "zone";
            update-type = "TXT";
          };
          knot-ds = {
            address = [
              "127.0.0.1"
              "::1"
            ];
            action = [ "query" "update" ];
            key = "knot-ds";
            update-owner = "name";
            update-owner-match = "equal";
            update-owner-name = [
              "_acme-challenge"
              "_acme-challenge.mail"
            ];
            update-type = "DS";
          };
          maddy-acme = {
            # Allow maddy to modify TXT records in _acme-challenge domains
            address = "::1";
            action = "update";
            key = "maddy";
            update-owner = "zone";
            update-type = "TXT";
          };
          transfer = {
            # Allow a zone transfer from local devices
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
          };
          workstation = {
            address = [
              "100.91.224.22"
              "fd7a:115c:a1e0:ab12:4843:cd96:625b:e016"
            ];
            key = "workstation";
            action = [ "query" "update" ];
            update-owner = "name";
            update-owner-match = "equal";
            update-owner-name = "_acme-challenge.workstation";
            update-type = "DS";
          };
        };
        mod-queryacl.local.address = [
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
        policy = {
          acme-challenge = {
            # Add a policy for acme challenge zones
            ds-push = "knot-ds-push";
            ksk-submission = "acme-challenge";
            ksk-lifetime = "14d";
            single-type-signing = true;
          };
          global = {
            # Add a DNSSEC policy with DS verfiication using unbound
            ksk-submission = "unbound";
            rrsig-refresh = "7d";
            propagation-delay = "1d";
            single-type-signing = true;
          };
        };
        remote = {
          "b.root-servers.net" = {
            address = [
              "2001:500:200::b"
              "199.9.14.201"
            ];
            automatic-acl = false;
          };
          "c.root-servers.net" = {
            address = [
              "2001:500:2::c"
              "192.33.4.12"
            ];
            automatic-acl = false;
          };
          "d.root-servers.net" = {
            address = [
              "2001:500:2d::d"
              "199.7.91.13"
            ];
            automatic-acl = false;
          };
          dnsmasq = {
            address = [
              "::1@56"
              "127.0.0.1@56"
            ];
            automatic-acl = false;
            block-notify-after-transfer = true;
          };
          "f.root-servers.net" = {
            address = [
              "2001:500:2f::f"
              "192.5.5.241"
            ];
            automatic-acl = false;
          };
          "g.root-servers.net" = {
            address = [
              "2001:500:12::d0d"
              "192.112.36.4"
            ];
            automatic-acl = false;
          };
          "ns1.first-ns.de".address = "2a01:4f8:0:a101::a:1";
          pc.address = [
            "fd7a:115c:a1e0::d2df:ec69@54"
            "100.95.236.105@54"
          ];
          "robotns2.second-ns.de".address = "2a01:4f8:0:1::5ddc:2";
          "robotns3.second-ns.com".address = "2001:67c:192c::add:a3";
          "k.root-servers.net" = {
            address = [
              "2001:7fd::1"
              "193.0.14.129"
            ];
            automatic-acl = false;
          };
          knot-ds-push = {
            address = [
              "::1@54"
              "127.0.0.1@54"
            ];
            key = "knot-ds";
            automatic-acl = false;
          };
          workstation = {
            address = [
              "100.91.224.22"
              "fd7a:115c:a1e0:ab12:4843:cd96:625b:e016"
            ];
            key = "workstation";
          };
          unbound = {
            address = "::1@55";
            automatic-acl = false;
          };
          "xfr.cjr.dns.icann.org" = {
            address = [
              "2620:0:2830:202::132"
              "192.0.47.132"
            ];
            automatic-acl = false;
          };
          "xfr.lax.dns.icann.org" = {
            address = [
              "2620:0:2d0:202::132"
              "192.0.32.132"
            ];
            automatic-acl = false;
          };
        };
        remotes = {
          hetzner.remote = [
            "ns1.first-ns.de"
            "robotns2.second-ns.de"
            "robotns3.second-ns.com"
          ];
          root-servers.remote = [
            "b.root-servers.net"
            "c.root-servers.net"
            "d.root-servers.net"
            "f.root-servers.net"
            "g.root-servers.net"
            "k.root-servers.net"
            "xfr.cjr.dns.icann.org"
            "xfr.lax.dns.icann.org"
          ];
        };
        server = {
          # Allow secondary servers to transfer zones from this server
          automatic-acl = true;

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
        submission = {
          acme-challenge.parent = [ "unbound" "knot-ds-push" "hetzner" ];
          # Check DS submittion using unbound
          unbound = {
            parent = "unbound";
            parent-delay = "48h";
          };
        };
        template = {
          default = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            # Add DNS cookies and rate limiting
            global-module = ["mod-cookies" "mod-rrl"];
            notify = "pc";
            semantic-checks = true;
          };
          catalog = {
            acl = [ "transfer" ];
            catalog-role = "generate";
            notify = "pc";
          };
          dnsmasq = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            ixfr-from-axfr = true;
            master = "dnsmasq";
            module = "mod-queryacl/local";
            notify = "pc";
            semantic-checks = true;
          };
          local = {
            # Template for zones that shouldn't be added to the catalog
            acl = [ "transfer" ];
            semantic-checks = true;
          };
          root-servers = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            dnssec-validation = true;
            ixfr-from-axfr = true;
            master = "root-servers";
            module = "mod-queryacl/local";
            notify = "pc";
            semantic-checks = true;
          };
          rDNS = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            file = "/etc/knot/rDNS.zone";
            module = [ "mod-queryacl/local" ];
            notify = "pc";
            reverse-generate = [
              "compsoc-dev.com"
              "home.arpa"
              "zandoodle.me.uk"
              "orion.home.arpa"
            ];
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          };
        };
        zone = lib.genAttrs (lib.genList (i: "${toString (i+64)}.100.in-addr.arpa") 64) (_: {template = "rDNS";})
        // {
          "." = {
            # Serve a copy of the root zone
            template = "root-servers";
            zonemd-verify = true;
          };
          "168.192.in-addr.arpa".template = "rDNS";
          "_acme-challenge.mail.zandoodle.me.uk" = {
            # Add a zone for ACME challenges
            acl = [ "maddy-acme" "transfer" ];
            dnssec-policy = "acme-challenge";
            dnssec-signing = true;
            file = "/etc/knot/acme-challenge.zandoodle.me.uk.zone";
            semantic-checks = true;
            template = "local";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "TXT";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          };
          "_acme-challenge.zandoodle.me.uk" = {
            # Add a zone for ACME challenges
            acl = [ "caddy-acme" "transfer" ];
            dnssec-policy = "acme-challenge";
            dnssec-signing = true;
            file = "/etc/knot/acme-challenge.zandoodle.me.uk.zone";
            semantic-checks = true;
            template = "local";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "TXT";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          };
          "_acme-challenge.workstation.zandoodle.me.uk" = {
            acl = [ "transfer" ];
            dnssec-validation = true;
            master = "workstation";
            template = "local";
            zonemd-verify = true;
          };
          arpa.template = "root-servers"; # Serve a copy of the root zone
          "bogus.zandoodle.me.uk" = {
            # Add a domain for DNSSEC testing
            acl = [ "transfer" ];
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          };
          "bogus-exists.zandoodle.me.uk" = {
            # Add a domain for DNSSEC testing
            acl = [ "transfer" ];
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            # Don't modify the zonefile
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          };
          catz.template = "catalog";
          "compsoc-dev.com" = {
            acl = [ "transfer" ];
            catalog-group = "global";
            dnssec-policy = "global";
            dnssec-signing = true;
            file = "/etc/knot/compsoc-dev.com.zone";
            notify = [ "hetzner" "pc" ];
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          };
          "d.f.ip6.arpa".template = "rDNS";
          "home.arpa" = {
            acl = [ "transfer" ];
            file = "/etc/knot/home.arpa.zone";
            module = "mod-queryacl/local";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          };
          "orion.home.arpa".template = "dnsmasq";
          "zandoodle.me.uk" = {
            acl = [ "knot-ds" "transfer" "workstation" ];
            catalog-group = "global";
            dnssec-policy = "global";
            dnssec-signing = true;
            file = "/etc/knot/zandoodle.me.uk.zone";
            notify = [ "hetzner" "pc" ];
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "DS";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          };
        };
      };
    };
    unbound = {
      enable = true;
      localControlSocketPath = "/run/unbound/unbound.ctl";
      package = pkgs.unbound-full;
      # Don't modify /etc/resolv.conf
      resolveLocalQueries = false;
      settings = {
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
          # Add eDNS cookies to the responses
          answer-cookie = true;
          # Allow querying localhost
          do-not-query-localhost = false;

          # Assume these domains are insecure and don't request DS records to prove it
          domain-insecure = [
            "broadband"
            "home.arpa"
            "168.192.in-addr.arpa."
            "d.f.ip6.arpa"
          ] ++ lib.genList (i: "${toString (i+64)}.100.in-addr.arpa") 64;

          # Enable Extended DNS Errors
          ede = true;
          ede-serve-expired = true;

          fast-server-permil = 900;

          http-notls-downstream = true;

          https-port = 8080;

          identity = "recusive.dns.zandoodle.me.uk";

          # Reply to queries from the same address the query was sent to
          interface-automatic = true;
          interface-automatic-ports = "\"55 8080\"";

          # Disable local zones for special domains
          local-zone = [
            "home.arpa. nodefault"
            "168.192.in-addr.arpa. nodefault"
            "d.f.ip6.arpa. nodefault"
          ] ++ lib.genList (i: "${toString (i+64)}.100.in-addr.arpa nodefault") 64;

          log-servfail = true;

          # Set the nsid
          nsid = "ascii_recursive.dns.zandoodle.me.uk";

          # Use all cores
          num-threads = 12;
          port = 55;

          prefer-ip6 = true;

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
          # Use the local root instance
          {
            name = ".";
            stub-addr = "::1@54";
            stub-first = true;
          }
          {
            name = "arpa";
            stub-addr = "::1@54";
            stub-first = true;
          }
          {
            # Query knot for zandoodle.me.uk
            name = "zandoodle.me.uk";
            stub-addr = "::1@54";
            stub-no-cache = true;
          }
          {
            # Query knot for compsoc-dev.com
            name = "compsoc-dev.com";
            stub-addr = "::1@54";
            stub-no-cache = true;
          }
          {
            # Query the home router for broadband
            name = "broadband";
            stub-addr = "192.168.1.1";
            stub-no-cache = true;
          }
          {
            # Query knot for home.arpa
            name = "home.arpa";
            stub-addr = "::1@54";
            stub-no-cache = true;
          }
          {
            # Query knot for 168.192.in-addr.arpa (192.168.0.0/16)
            name = "168.192.in-addr.arpa";
            stub-addr = "::1@54";
            stub-no-cache = true;
          }
          {
            # Query knot for d.f.ip6.arpa (fd00::/8)
            name = "d.f.ip6.arpa";
            stub-addr = "::1@54";
            stub-no-cache = true;
          }
        ] ++ lib.genList (i: {
          name = "${toString (i+64)}.100.in-addr.arpa";
          stub-addr = "::1@54";
          stub-no-cache = true;
        }) 64;
      };
    };
  };
  systemd = {
    packages = [
      # Add the dnsdist service
      pkgs-unstable.${config.nixpkgs.system}.dnsdist
    ];
    services = {
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
      dnsmasq = {
        confinement.enable = true;
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE";
          BindReadOnlyPaths = [
            "/etc/passwd"
            "/run/dbus/system_bus_socket"
            "/run/systemd/journal/dev-log"
          ];
          CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE";
          Group = "dnsmasq";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          # Add the dnsmasq cgroup to the services table
          NFTSet = "cgroup:inet:services:dnsmasq";
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateUsers = lib.mkForce false;
          ProcSubset = "pid";
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = lib.mkForce "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_NETLINK AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "dnsmasq";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          User = "dnsmasq";
        };
        preStart = lib.mkForce ''
          dnsmasq --test -C ${config.services.dnsmasq.configFile}
        '';
      };
      knot.serviceConfig = {
        # Get the TSIG credentials for caddy
        LoadCredential = [
          "caddy:/run/keymgr/caddy"
          "maddy:/run/keymgr/maddy"
          "knot-ds:/run/keymgr/knot-ds"
        ];

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
          "acme-challenge.zandoodle.me.uk.zone"
          "bogus.zandoodle.me.uk.zone"
          "compsoc-dev.com.zone"
          "home.arpa.zone"
          "letsencrypt.zone.include"
          "letsencrypt-dane.zone.include"
          "no-email.zone.include"
          "rDNS.zone"
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
      unbound.serviceConfig.NFTSet = "cgroup:inet:services:unbound";
    };
    targets.knot-reload = {
      description = "Restart knot-reload service";
      conflicts = [ "knot-reload.service" ];
      unitConfig.StopWhenUnneeded = true;
      onSuccess = [ "knot-reload.service" ];
    };
  };
  users = {
    groups = {
      ddns = {};
      dnsdist = {};
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
    };
  };
}
