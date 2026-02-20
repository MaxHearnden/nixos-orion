{ config, lib, pkgs, pkgs-unstable, utils, ... }:

let dnsdist = pkgs.callPackage ./dnsdist.nix {}; in
{
  environment.etc = {
    "dnsdist/dnsdist.conf".text = ''
      -- listen on all IPv4 and IPv6 addresses
      addLocal("0.0.0.0:53", {enableProxyProtocol = false})
      addLocal("[::]:53", {enableProxyProtocol = false})
      addLocal("[::1]:58")

      setProxyProtocolACL({"::1"})

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
      newServer({address = "[::1]:57", name = "unbound", pool = "iterative", healthCheckMode = "lazy", useProxyProtocol = true})
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

      addAction(AllRule(), RCodeAction(DNSRCode.NOTAUTH, {ra = false}))
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
      ; Advertise our public IP address as the IP address for compsoc-dev.com
      $INCLUDE /var/lib/ddns/zonefile

      ; Advertise the authoritative nameserver
      @ ns dns.zandoodle.me.uk.
      ; Advertise Hetzner secondary nameservers
      @ ns ns1.first-ns.de.
      @ ns robotns2.second-ns.de.
      @ ns robotns3.second-ns.com.

      ; Setup mail for this domain
      @ mx 10 mail.zandoodle.me.uk.
      @ txt "v=spf1 redirect=_spf.zandoodle.me.uk"

      ; Add google site verification
      @ txt "google-site-verification=oZJUabY5f9TzTiPw8Ml-k8GrRILLRbITIEF8eamsLY4"

      ; Advertise HTTP/2 and HTTP/3 support
      @ HTTPS 1 . alpn=h3,h2

      ; Setup certificate authority restrictions
      @ caa 0 issuemail ";"
      @ caa 0 issuevmc ";"
      @ caa 0 issuewild ";"
      ; Only Let's Encrypt can issue for this domain and only using the dns-01 validation method
      @ caa 128 issue "letsencrypt.org;validationmethods=dns-01"

      _acme-challenge cname _acme-challenge.zandoodle.me.uk.
      _dmarc cname _dmarc.zandoodle.me.uk.

      default._domainkey TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs9i5JfSz0iOz0L5xG9OwO8N9bdhY+YT+Hq3AVCupqZmp487NTem0yoPEgfZDqVxGaTFVdCxAMhHHvv08jo6U5Cmubumo8HHGzwvYJux9CCWcbUFlr3994Avs04O5sDSXmeDDuG9rGZmepy0r+Gly0brAKEv6UxM2l1HnBB2qabkCzYUamc9TyH8BUM9PIj3RWVEO/FHo8XjYxwrMLd22inHQ8wAORc3ERXqEEe/XgaxnWmD4ledoqRF8imcmqClXN+2f7+WvsJo+/ovi5Oh7+8WfLyx9KVWwjWHPgd6a9Dm/ArSjiZbzR+DpynQZi+AvUXIxBpeQXlvofl0W+479pwIDAQAB"

      _mta-sts cname _mta-sts.zandoodle.me.uk.

      ; Advertise DANE
      _tcp dname _tcp.zandoodle.me.uk.

      _tls dname _tls.zandoodle.me.uk.

      flag-0be5c4b29b type65534 \# 0
      flag-0be5c4b29b txt "v=spf1 -all"

      mail mx 10 mail.zandoodle.me.uk.
      mail txt "v=spf1 mx -all"

      default._domainkey.mail txt "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+wMyRqY5sX/bHyuyYlSHM3N0tEqoCV6zQnSjMwCrxoETQsBx6ceXvFmEW1JCE9rp2l+DVDFk9IUVhvMUqHfC+NBKDojqX7PX4gNHrP+E6wkmPRuNzff07dHMSRat1pugpleP9oJgffJBjpGh/YpROsDbpOhlggd5gQjkgP2hH6JsrEwPtdRA/VBqGi6fonSpP9aWB19GVEKAx1xnpaZy991mzcpPSGhXXlOLXM6tgDthBEk0KCcJ3nKoIzbiDRc9oWRlyBxfOND2DYiDMVV02D2ykswCGb5GKhJ4Dy6KbFr9jbUo4h8zdN765P52Phd+tddDOVCbA9xyUI4rTZmkwIDAQAB"

      _mta-sts.mail cname _mta-sts.zandoodle.me.uk.
      _tls.mail dname _tls.zandoodle.me.uk.

      mta-sts.mail cname @
      _acme-challenge.mta-sts.mail cname _acme-challenge.zandoodle.me.uk.

      mta-sts cname @
      _acme-challenge.mta-sts cname _acme-challenge.zandoodle.me.uk.
      ollama cname local-tailscale.zandoodle.me.uk.
      _acme-challenge.ollama cname _acme-challenge.zandoodle.me.uk.
      _tcp.ollama dname _tcp.zandoodle.me.uk.
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
      workstation ns workstation.zandoodle.me.uk.
    '';
    "knot/int.zandoodle.me.uk.zone".text = ''
      @ soa local-tailscale.zandoodle.me.uk. hostmaster.zandoodle.me.uk. 0 14400 3600 604800 86400
      @ ns dns.zandoodle.me.uk.
      @ txt "This is meant to be public, this is just for stuff where I don't care about being able to resolve it over IPv4"

      ; Setup an extant domain for DNSSEC testing
      bogus-exists type65534 \# 0

      chromebook a 100.69.85.70
      $INCLUDE /etc/knot/no-email.zone.include chromebook.int.zandoodle.me.uk.
      chromebook aaaa fd7a:115c:a1e0::d401:5546
      chromebook sshfp 1 2 dc6283b6624010239844b07c3c6e4691233ceb4a46c86c36402cfcfe3a1eceda
      chromebook sshfp 4 2 522f2d5021c6d6250d99b77bea672fbfaac6c5b8a4ef6950d49267da9ecc11ee
      _kerberos.chromebook txt WORKSTATION.ZANDOODLE.ME.UK

      dell a 100.70.43.93
      $INCLUDE /etc/knot/no-email.zone.include dell.int.zandoodle.me.uk.
      dell aaaa fd7a:115c:a1e0::4cc6:2b5d
      dell sshfp 1 2 067c422d29d32b2c540b2428a45deeab53baa930dab328a7f6836b5876e6eb97
      dell sshfp 4 2 75c4d82ea3be8b5385f5a2a89b97f1677dfc77c2830b71ee39de7944d3d6ed9f
      _kerberos.dell txt WORKSTATION.ZANDOODLE.ME.UK

      laptop a 100.68.198.4
      $INCLUDE /etc/knot/no-email.zone.include laptop.int.zandoodle.me.uk.
      laptop aaaa fd7a:115c:a1e0::d601:c604
      laptop sshfp 1 2 74f8b963573c943f69119ed3383dcf34471acc5ac61e6136cc7daddce57e9dad
      laptop sshfp 4 2 af1162523e3f11a434bec1a78f6b8c5bf0b9f5c187391a08004afb8b5d7d8195
      _kerberos.laptop txt WORKSTATION.ZANDOODLE.ME.UK

      orion cname local-tailscale.zandoodle.me.uk.

      pc a 100.95.236.105
      $INCLUDE /etc/knot/no-email.zone.include pc.int.zandoodle.me.uk.
      pc aaaa fd7a:115c:a1e0::d2df:ec69
      pc sshfp 1 2 ea259e9d2d355d9506919e56ed0c35fbb0476501524f6349cf9f6ef6dbe19c50
      pc sshfp 4 2 7191d7ac7c0eaa18df828f22b4b948e2efc6281c3ca7aab5a78a5beef4b30d5b
      _acme-challenge.pc ns dns.zandoodle.me.uk.
      _kerberos.pc txt WORKSTATION.ZANDOODLE.ME.UK

      tcp-fallback txt "${lib.strings.replicate 4096 "a"}"
    '';
    "knot/letsencrypt.zone.include".source =
      pkgs.callPackage ./gen-TLSA.nix {
        names = [ "ISRG_Root_X1" "ISRG_Root_X2" ];
      };
    "knot/letsencrypt-dane.zone.include".source =
      pkgs.callPackage ./gen-TLSA.nix {
        names = [
          "e7-cross.der"
          "e8-cross.der"
          "e9-cross.der"
          "root-x2-by-x1.der"
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
      $INCLUDE /var/lib/ddns/zonefile

      ; Advertise the primary DNS server
      @ ns dns
      ; Advertise Hetzner secondary nameservers
      @ ns ns1.first-ns.de.
      @ ns robotns2.second-ns.de.
      @ ns robotns3.second-ns.com.

      ; Setup mail exchanges for this domain
      @ mx 10 mail

      ; Google stuff
      @ txt "google-site-verification=ZDVckD_owTCKFzcbI9VqqGQOoNfd_8C0tKNqRVkiK8I"

      ; Setup SPF and DMARC for this domain
      @ txt "v=spf1 redirect=_spf.zandoodle.me.uk"

      ; Advertise HTTP/2 and HTTP/3 support for zandoodle.me.uk
      @ https 1 . alpn=h3,h2

      ; Setup certificate authority restrictions for this domain
      @ caa 0 issuemail ";"
      @ caa 0 issuevmc ";"
      @ caa 0 issuewild ";"
      ; Only Let's Encrypt can issue for this domain and only using the dns-01 validation method
      @ caa 128 issue "letsencrypt.org;validationmethods=dns-01"

      _acme-challenge ns dns

      ; Setup DMARC
      _dmarc txt "v=DMARC1;p=reject;aspf=s;adkim=s;fo=d;rua=mailto:dmarc-reports@zandoodle.me.uk;ruf=mailto:dmarc-reports@zandoodle.me.uk"
      compsoc-dev.com._report._dmarc txt "v=DMARC1;"

      ; Setup DKIM for this domain
      default._domainkey TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCuGmFxA7aupe8x7tmSolntpa5qBxyQnGkgsfjyjD57doP55a57KXTxEo6t7buBpua/W6dktcw2zpLp9338yg1wA/9RJwhZclzrH5Kv4gNbMHHvhBbygnoJqbrwFH8+VDNG4NKUl5WKFRiITJXd8Y0xqpPhFwfmd2nITjc8wleGv4eQXmB5ytP8Nj2fE6pd4fGpF7sydnOo5BTBSeb0QtmgbQcReQ05CqwMGEAyKOQFnKMzEAOEtvyXUFyG7hFt4ZsngpRGDM/1d4rI/Kh7oCFfzuhR+ENhZkLqYz9xZ0QZ3GWVon7mXfiVvJL5GBfb9cwLjAGp5QhgN2El2yc/3/QIDAQAB"

      _kerberos uri 5 1 krb5srv:m:kkdcp:https://zandoodle.me.uk/KdcProxy
      _kerberos uri 10 1 krb5srv:m:udp:local.zandoodle.me.uk
      _kerberos uri 20 1 krb5srv:m:tcp:local.zandoodle.me.uk
      _kerberos txt ZANDOODLE.ME.UK
      _kerberos-adm uri 5 1 krb5srv:m:kkdcp:https://zandoodle.me.uk/KdcProxy
      _kerberos-adm uri 10 1 krb5srv:m:tcp:local.zandoodle.me.uk

      ; Setup MTA-STS for this domain
      _mta-sts txt "v=STSv1; id=1"

      _kerberos.tailscale._sites uri 5 1 krb5srv:m:kkdcp:https://local-tailscale.zandoodle.me.uk/KdcProxy
      _kerberos.tailscale._sites uri 10 1 krb5srv:m:udp:local-tailscale.zandoodle.me.uk
      _kerberos.tailscale._sites uri 20 1 krb5srv:m:tcp:local-tailscale.zandoodle.me.uk
      _kerberos-adm.tailscale._sites uri 5 1 krb5srv:m:kkdcp:https://local-tailscale.zandoodle.me.uk/KdcProxy
      _kerberos-adm.tailscale._sites uri 20 1 krb5srv:m:tcp:local-tailscale.zandoodle.me.uk
      _kerberos._tcp.tailscale._sites srv 0 10 88 local-tailscale
      _kerberos-adm._tcp.tailscale._sites srv 0 10 749 local-tailscale
      _kerberos._udp.tailscale._sites srv 0 10 88 local-tailscale

      _spf txt "v=spf1 ?a:mail.zandoodle.me.uk -all"

      ; Setup DANE for this domain
      $INCLUDE /etc/knot/letsencrypt.zone.include *._tcp.zandoodle.me.uk.

      ; Setup SRV records
      _imaps._tcp SRV 0 10 993 imap
      _kerberos._tcp srv 0 10 88 local
      _kerberos-adm._tcp srv 0 10 749 local
      _submissions._tcp SRV 0 10 465 smtp
      _submission._tcp SRV 0 10 587 smtp

      ; Setup TLSRPT
      _smtp._tls txt "v=TLSRPTv1;rua=mailto:tlsrpt@zandoodle.me.uk"

      _kerberos._udp srv 0 10 88 local

      cardgames cname @
      _acme-challenge.cardgames cname _acme-challenge
      wss.cardgames cname @
      _acme-challenge.wss.cardgames cname _acme-challenge

      ; NS targets musn't be an alias
      $INCLUDE /var/lib/ddns/zonefile-ipv6-only dns.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include dns.zandoodle.me.uk.

      _acme-challenge.dns cname _acme-challenge

      dot-check\. txt dot\ check
      dot-check\. txt "v=spf1 -all"

      imap cname local-tailscale
      _acme-challenge.imap cname mail._acme-challenge

      int ns dns

      $INCLUDE /var/lib/ddns/local-zonefile local.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local.zandoodle.me.uk.

      ; Advertise HTTP/2 and HTTP/3 support for local.zandoodle.me.uk
      local HTTPS 1 . alpn=h3,h2

      ; Public SSH key fingerprints for local domains
      local IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81
      _acme-challenge.local cname _acme-challenge
      _tcp.local dname _tcp

      $INCLUDE /var/lib/ddns/local-guest-zonefile local-guest.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local-guest.zandoodle.me.uk.
      local-guest IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local-guest IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81

      local-shadow A 192.168.4.1
      local-shadow AAAA fd09:a389:7c1e:1::1
      $INCLUDE /etc/knot/no-email.zone.include local-shadow.zandoodle.me.uk.
      local-shadow IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local-shadow IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81

      ; Advertise IP addresses for this domain
      $INCLUDE /var/lib/ddns/local-tailscale-zonefile local-tailscale.zandoodle.me.uk.
      $INCLUDE /etc/knot/no-email.zone.include local-tailscale.zandoodle.me.uk.
      ; Public SSH key fingerprints for local domains
      local-tailscale IN SSHFP 1 2 ab797327e7a122d79bed1df5ebee639bf2a0cdb68e0e2cef4be62439333d028e
      local-tailscale IN SSHFP 4 2 1a775110beae6e379adcd0cc2ea510bfb12b077883016754511103bd3a550b81

      _acme-challenge.local-tailscale cname _acme-challenge

      ; MX targets musn't be an alias
      $INCLUDE /var/lib/ddns/zonefile mail.zandoodle.me.uk.
      mail mx 10 mail
      mail txt "v=spf1 a -all"

      _acme-challenge.mail cname mail._acme-challenge

      default._domainkey.mail txt "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1VJx8wBBOAQWOk+6i7MuJel5lV7glADvBG3g+UcW5wn/mbGJdsyGpoI33694ZSBth4y3OHeVP11ydIznHY0fuBviAKVyLQZN94j5Nw4rH4xZXGhHXxUqBcMuHKHrj5jp2cd/rgtCX18W8YkSYEU6yZpbjle8NoMFRK5OFuLNeni7jOtPGE3P7JyfzY0umkiLemVn5w/HREf0i6un7DJ/iq3OG3Pd3MWxbcIYwRf3+zpRybjOTwgBhfHXNysJ8QZiz5fg3wCYzEYy2AyXbhF2PZNqZrId3oaFiGGhX13ffUSVGdR7VS9zwmIQoEG+jrOitMocywf8X1HIeB5m8zfHWwIDAQAB"

      _mta-sts.mail cname _mta-sts

      $INCLUDE /etc/knot/letsencrypt-dane.zone.include _25._tcp.mail.zandoodle.me.uk.

      _tls.mail dname _tls

      mta-sts.mail cname @
      _acme-challenge.mta-sts.mail cname _acme-challenge
      mta-sts cname @
      _acme-challenge.mta-sts cname _acme-challenge

      multi-string-check TXT string 1 string 2
      multi-string-check txt "v=spf1 -all"

      ; Check that null bytes within TXT records are handled correctly
      null-check TXT "\000"
      null-check txt "v=spf1 -all"

      ; Check that null bytes within domains are handled correctly
      null-domain-check\000 TXT "null domain check"

      smtp cname local-tailscale
      _acme-challenge.smtp cname mail._acme-challenge

      ; Add a zero ttl record for testing DNS resolvers
      ttl-check 0 txt ttl\ check
      ttl-check 0 txt "v=spf1 -all"

      workstation a 100.91.224.22
      $INCLUDE /etc/knot/no-email.zone.include workstation.zandoodle.me.uk.
      workstation aaaa fd7a:115c:a1e0:ab12:4843:cd96:625b:e016
      workstation IN SSHFP 1 2 bb26ac7d22088477cf1a3f701f702595025a569c7373306bbfb44d880202322f
      workstation IN SSHFP 4 2 7fa4a718df8a2c3fe600f3d9976d00ac825d56a1ca41b5b36026a279400642e8
      workstation caa 128 issue "letsencrypt.org;validationmethods=dns-01"
      workstation caa 0 issuemail ";"
      workstation caa 0 issuevmc ";"
      *.workstation cname workstation
      _acme-challenge.workstation ns dns
      _kerberos.workstation txt WORKSTATION.ZANDOODLE.ME.UK
      _kerberos.workstation uri 5 1 krb5srv:m:kkdcp:https://kkdcp.workstation.zandoodle.me.uk/
      _kerberos.workstation uri 10 1 krb5srv:m:tcp:workstation.zandoodle.me.uk
      _kerberos-adm.workstation uri 5 1 krb5srv:m:kkdcp:https://kkdcp.workstation.zandoodle.me.uk/
      _kerberos-adm.workstation uri 20 1 krb5srv:m:tcp:workstation.zandoodle.me.uk
      _kerberos._tcp.workstation srv 0 10 88 workstation
      _kerberos-adm._tcp.workstation srv 0 10 749 workstation
      _kerberos._udp.workstation srv 0 10 88 workstation
      test.workstation cname workstation
      _kerberos.test.workstation uri 5 1 krb5srv:m:kkdcp:https://kkdcp.workstation.zandoodle.me.uk/
      _kerberos.test.workstation uri 10 1 krb5srv:m:tcp:workstation.zandoodle.me.uk:8088
      _kerberos._tcp.test.workstation srv 0 10 8088 workstation
      _kerberos._udp.test.workstation srv 0 10 8088 workstation
    '';
    "resolv.conf".text = ''
      # Use the local DNS resolver
      nameserver ::1
      nameserver 127.0.0.1

      search int.zandoodle.me.uk zandoodle.me.uk home.arpa orion.home.arpa

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

        dhcp-fqdn = true;

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
          "tag:guest,option6:dns-server,fd09:a389:7c1e:4:7006:83ff:feff:5d0c"
          "tag:shadow,option6:dns-server,fd09:a389:7c1e:1::1"
          "option:domain-search,orion.home.arpa,home.arpa"
        ];
        dhcp-match = "set:has-routes,55,!";
        # Enable DHCP and allocate from a suitable IP address range
        dhcp-range = [
          "tag:has-routes,set:guest,192.168.5.2,192.168.5.199,1d"
          "tag:!has-routes,set:guest,192.168.6.2,192.168.6.199,1d"
          "set:guest,fd09:a389:7c1e:4::,fd09:a389:7c1e:4:ffff:ffff:ffff:ffff,64,1d"
          "set:shadow,192.168.4.2,192.168.4.199,1d"
          "set:shadow,fd09:a389:7c1e:1::,fd09:a389:7c1e:1:ffff:ffff:ffff:ffff,64,1d"
          "fd09:a389:7c1e:5::,fd09:a389:7c1e:5:ffff:ffff:ffff:ffff,64,1d"
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
        "/etc/knot/pc.tsig"
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
            update-owner-match = "equal";
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
              "int"
            ];
            update-type = "DS";
          };
          maddy-acme = {
            # Allow maddy to modify TXT records in _acme-challenge domains
            address = "::1";
            action = "update";
            key = "maddy";
            update-owner = "name";
            update-owner-match = "equal";
            update-owner-name = [
              "mail"
            ];
            update-type = "TXT";
          };
          pc = {
            action = [ "query" "update" ];
            remote = "pc";
            update-owner = "name";
            update-owner-match = "equal";
            update-owner-name = "_acme-challenge.pc";
            update-type = "DS";
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
            action = [ "query" "update" ];
            remote = "workstation";
            update-owner = "name";
            update-owner-match = "equal";
            update-owner-name = "_acme-challenge.workstation";
            update-type = "DS";
          };
        };
        log.syslog.any = "notice";
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
          subdomain = {
            # Add a policy for acme challenge zones
            ds-push = "knot-ds-push";
            ksk-submission = "subdomain";
            ksk-lifetime = "14d";
            single-type-signing = true;
          };
          global = {
            # Add a DNSSEC policy with DS verfiication using unbound
            ksk-lifetime = "30d";
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
          pc = {
            address = "fd7a:115c:a1e0::d2df:ec69@54";
            key = "pc";
          };
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
            address = "fd7a:115c:a1e0:ab12:4843:cd96:625b:e016@54";
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
          listen = ["0.0.0.0@54" "::@54" "/run/knot/global_query"];

          # Set an identity for NSID
          nsid = "dns.zandoodle.me.uk";

          # Allow TCP Fast Open
          tcp-fastopen = true;

          # Open multiple TCP sockets
          tcp-reuseport = true;
        };
        submission = {
          subdomain.parent = [ "unbound" "knot-ds-push" "hetzner" ];
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
            notify = [ "pc" "workstation" ];
            semantic-checks = true;
          };
          catalog = {
            acl = [ "transfer" ];
            catalog-role = "generate";
            notify = [ "pc" "workstation" ];
          };
          dnsmasq = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            ixfr-from-axfr = true;
            master = "dnsmasq";
            module = "mod-queryacl/local";
            notify = [ "pc" "workstation" ];
            semantic-checks = true;
          };
          icann = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            dnssec-validation = true;
            ixfr-from-axfr = true;
            master = ["xfr.cjr.dns.icann.org" "xfr.lax.dns.icann.org"];
            module = "mod-queryacl/local";
            notify = [ "pc" "workstation" ];
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
            notify = [ "pc" "workstation" ];
            semantic-checks = true;
          };
          rDNS = {
            acl = [ "transfer" ];
            catalog-role = "member";
            catalog-zone = "catz";
            file = "/etc/knot/rDNS.zone";
            module = [ "mod-queryacl/local" ];
            notify = [ "pc" "workstation" ];
            reverse-generate = [
              "compsoc-dev.com"
              "home.arpa"
              "int.zandoodle.me.uk"
              "zandoodle.me.uk"
              "orion.home.arpa"
              "workstation.home.arpa"
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
          "_acme-challenge.zandoodle.me.uk" = {
            # Add a zone for ACME challenges
            acl = [ "caddy-acme" "maddy-acme" "transfer" ];
            dnssec-policy = "subdomain";
            dnssec-signing = true;
            file = "/etc/knot/acme-challenge.zandoodle.me.uk.zone";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "TXT";
            zonemd-generate = "zonemd-sha512";
            zonefile-sync = -1;
          };
          "_acme-challenge.pc.int.zandoodle.me.uk" = {
            acl = [ "transfer" ];
            dnssec-validation = true;
            master = "pc";
            notify = "workstation";
            zonemd-verify = true;
          };
          "_acme-challenge.workstation.zandoodle.me.uk" = {
            acl = [ "transfer" ];
            dnssec-validation = true;
            master = "workstation";
            notify = "pc";
            zonemd-verify = true;
          };
          arpa.template = "root-servers"; # Serve a copy of the root zone
          "bogus.int.zandoodle.me.uk" = {
            # Add a domain for DNSSEC testing
            acl = [ "transfer" ];
            file = "/etc/knot/bogus.zandoodle.me.uk.zone";
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          };
          "bogus-exists.int.zandoodle.me.uk" = {
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
            notify = [ "hetzner" "pc" "workstation" ];
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
          "in-addr.arpa".template = "icann";
          "int.zandoodle.me.uk" = {
            acl = [ "pc" "transfer" ];
            dnssec-policy = "subdomain";
            dnssec-signing = true;
            file = "/etc/knot/int.zandoodle.me.uk.zone";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "DS";
            zonefile-sync = -1;
          };
          "ip6.arpa".template = "icann";
          "ipv4only.arpa" = {
            dnssec-validation = false;
            template = "icann";
          };
          "orion.home.arpa".template = "dnsmasq";
          "root-servers.net" = {
            dnssec-validation = false;
            template = "root-servers";
          };
          "workstation.home.arpa" = {
            master = "workstation";
            module = "mod-queryacl/local";
            notify = "pc";
          };
          "zandoodle.me.uk" = {
            acl = [ "knot-ds" "transfer" "workstation" ];
            catalog-group = "global";
            dnssec-policy = "global";
            dnssec-signing = true;
            file = "/etc/knot/zandoodle.me.uk.zone";
            notify = [ "hetzner" "pc" "workstation" ];
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

          dns64-prefix = "fd09:a389:7c1e:3::/64";
          dns64-ignore-aaaa = "vodafone.broadband";

          # Allow querying localhost
          do-not-query-localhost = false;

          # Assume these domains are insecure and don't request DS records to prove it
          domain-insecure = [
            "broadband"
            "home.arpa"
            "168.192.in-addr.arpa."
            "d.f.ip6.arpa"
            "root-servers.net"
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
          interface-automatic-ports = "\"55 57 8080\"";

          # Disable local zones for special domains
          local-zone = [
            ". inform"
            "168.192.in-addr.arpa. nodefault"
            "39.118.92.in-addr.arpa. refuse"
            "92.94.80.in-addr.arpa. refuse"
            "corp.nai.org. deny"
            "d.f.ip6.arpa. nodefault"
            "home.arpa. nodefault"
          ] ++ lib.genList (i: "${toString (i+64)}.100.in-addr.arpa nodefault") 64;

          log-servfail = true;

          module-config = "\"respip dns64 validator iterator\"";

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

          proxy-protocol-port = 57;

          response-ip = [
            "fd09:a389:7c1e:3::/64 redirect"
            "fd09:a389:7c1e:3:c0:0:aa00::/103 always_transparent"
            "fd09:a389:7c1e:3:c0:a800::/88 always_transparent"
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
            stub-first = true;
          }
          {
            name = "int.zandoodle.me.uk";
            stub-addr = "::1@54";
          }
          {
            name = "_acme-challenge.zandoodle.me.uk";
            stub-addr = "::1@54";
          }
          {
            name = "_acme-challenge.workstation.zandoodle.me.uk";
            stub-addr = "::1@54";
          }
          {
            name = "_acme-challenge.pc.int.zandoodle.me.uk";
            stub-addr = "::1@54";
          }
          {
            # Query knot for compsoc-dev.com
            name = "compsoc-dev.com";
            stub-addr = "::1@54";
            stub-first = true;
          }
          {
            # Query the home router for broadband
            name = "broadband";
            stub-addr = "192.168.1.1";
          }
          {
            # Query knot for home.arpa
            name = "home.arpa";
            stub-addr = "::1@54";
          }
          {
            # Query knot for 168.192.in-addr.arpa (192.168.0.0/16)
            name = "168.192.in-addr.arpa";
            stub-addr = "::1@54";
          }
          {
            # Query knot for d.f.ip6.arpa (fd00::/8)
            name = "d.f.ip6.arpa";
            stub-addr = "::1@54";
          }
          {
            name = "in-addr.arpa";
            stub-addr = "::1@54";
            stub-first = true;
          }
          {
            name = "ip6.arpa";
            stub-addr = "::1@54";
            stub-first = true;
          }
          {
            name = "root-servers.net";
            stub-addr = "::1@54";
            stub-first = true;
          }
          {
            name = "ipv4only.arpa";
            stub-addr = "::1@54";
            stub-first = true;
          }
        ] ++ lib.genList (i: {
          name = "${toString (i+64)}.100.in-addr.arpa";
          stub-addr = "::1@54";
        }) 64;
      };
    };
  };
  systemd = {
    packages = [
      # Add the dnsdist service
      dnsdist
    ];
    services = {
      dnsdist = {
        serviceConfig = {
          # Override the dnsdist service to use /etc/dnsdist/dnsdist.conf
          ExecStart = [
            ""
            "${lib.getExe dnsdist} --supervised --disable-syslog --config /etc/dnsdist/dnsdist.conf"
          ];
          ExecStartPre = [
            ""
            "${lib.getExe dnsdist} --check-config --config /etc/dnsdist/dnsdist.conf"
          ];

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
        after = [ "network-online.target" "tailscale.service" ];
        # Create a minimal sandbox for this service
        confinement.enable = true;
        # Reload the DNS zone after getting the IP address
        onSuccess = [ "knot-reload.target" ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "/var/run/nscd"
            "/etc/ssl/certs/ca-certificates.crt"
          ];

          # Don't allow get-IP-address to change the system
          CapabilityBoundingSet = "";

          # Use a dedicated user
          Group = "ddns";

          LoadCredential = "mail_password:/etc/ddns/mail_password";

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
          RestrictAddressFamilies = "AF_NETLINK AF_INET AF_INET6 AF_UNIX";

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
          ${lib.getExe' pkgs.iproute2 "ip"} -json -6 address show dev bridge to 2000::/3 -temporary | ${lib.getExe pkgs.jq} -r \
            '.[].addr_info.[].local // empty' >/run/ddns/IPv6-address

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
            ${lib.getExe' pkgs.dos2unix "unix2dos"} <<EOF | ${lib.getExe' pkgs.msmtp "sendmail"} --user=ddns@zandoodle.me.uk --read-envelope-from --passwordeval="cat /run/credentials/get-IP-address.service/mail_password" --tls=on --tls-starttls=off --host=smtp.zandoodle.me.uk --port=465 --auth=on -t
          From: ddns@zandoodle.me.uk
          To: ddns-mail@zandoodle.me.uk
          Subject: DDNS update to $(</run/ddns/IPv6-address)

          Your public zonefile has been updated to:
          $(</run/ddns/zonefile)

          EOF
            ${lib.getExe pkgs.hcloud} --config /var/lib/ddns/hcloud.toml zone change-primary-nameservers zandoodle.me.uk --primary-nameservers-file - <<EOF
            [
              {
                "address": "$(</run/ddns/IPv6-address)",
                "port": 53
              }
            ]
          EOF
            ${lib.getExe pkgs.hcloud} --config /var/lib/ddns/hcloud.toml zone change-primary-nameservers compsoc-dev.com --primary-nameservers-file - <<EOF
            [
              {
                "address": "$(</run/ddns/IPv6-address)",
                "port": 53
              }
            ]
          EOF
          fi

          # Move the verified data from /run/ddns to /var/lib/ddns
          ${lib.getExe' pkgs.coreutils "mv"} -f /run/ddns/IPv4-address \
            /run/ddns/zonefile /run/ddns/local-zonefile /run/ddns/local-guest-zonefile /run/ddns/zonefile-ipv6-only /run/ddns/local-tailscale-zonefile /var/lib/ddns/
        '';
        unitConfig.StartLimitIntervalSec = "20m";
        wants = [ "network-online.target" "tailscale.service" ];
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
          "int.zandoodle.me.uk.zone"
          "letsencrypt.zone.include"
          "letsencrypt-dane.zone.include"
          "no-email.zone.include"
          "rDNS.zone"
          "zandoodle.me.uk.zone"
        ];
        serviceConfig = {
          BindReadOnlyPaths = "/run/knot/knot.sock";
          CapabilityBoundingSet = "";
          ExecStart = utils.escapeSystemdExecArgs [
            "${lib.getExe' pkgs.knot-dns "knotc"}"
            "zone-reload"
            "_acme-challenge.zandoodle.me.uk"
            "bogus.int.zandoodle.me.uk"
            "bogus-exists.int.zandoodle.me.uk"
            "compsoc-dev.com"
            "home.arpa"
            "int.zandoodle.me.uk"
            "zandoodle.me.uk"
          ];
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
    };
    targets.knot-reload = {
      description = "Restart knot-reload service";
      conflicts = [ "knot-reload.service" ];
      unitConfig.StopWhenUnneeded = true;
      onSuccess = [ "knot-reload.service" ];
    };
    timers.get-IP-address = {
      timerConfig = {
        # Start the unit on boot
        OnBootSec = "0";
        OnUnitActiveSec = "1h";
      };
      wantedBy = [ "timers.target" ];
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
