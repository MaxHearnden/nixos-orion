{ lib, pkgs, ... }: {
  environment.etc = {
    "postfix-ssl.conf".text = ''
      postfix = postfix_settings

      [postfix_settings]
      ssl_conf = postfix_ssl_settings

      [postfix_ssl_settings]
      system_default = baseline_postfix_settings

      [baseline_postfix_settings]
      SignatureAlgorithms = ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA512:RSA+SHA256:RSA+SHA384
    '';
    "sasl2/smtpd.conf".text = ''
      keytab: /var/lib/postfix/krb5.keytab
      mech_list: GSSAPI PLAIN LOGIN
      pwcheck_method: auxprop
      auxprop_plugin: sasldb
      service_principal: *
    '';
  };
  services = {
    caddy.virtualHosts = {
      "imap.int.zandoodle.me.uk".extraConfig = ''
        tls {
          issuer acme {
            dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
            profile shortlived
          }
        }

        abort
      '';
      "smtp.int.zandoodle.me.uk".extraConfig = ''
        tls {
          issuer acme {
            dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
            profile shortlived
          }
        }

        abort
      '';
      "mail.zandoodle.me.uk".extraConfig = ''
        tls {
          issuer acme {
            dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
            profile shortlived
          }
        }

        abort
      '';
    };
    cyrus-imap = {
      enable = true;
      cyrusSettings.DAEMON.idle.cmd = [
        "idled"
      ];
      imapdSettings = {
        allowstarttls = true;
        autocreate_quota = 0;
        defaultdomain = "workstation.zandoodle.me.uk";
        defaultpartition = "default";
        partition-default = "/var/lib/cyrus/storage";
        loginrealms = "workstation.zandoodle.me.uk";
        sasl_keytab = "/var/lib/cyrus/krb5.keytab";
        sasl_mech_list = "GSSAPI";
        sasl_service_principal = "*";
        tls_required = true;
        tls_eccurve = "auto";
        tls_versions = "tls1_2 tls1_3";
        tls_prefer_server_ciphers = true;
        tls_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305";
        tls_server_cert = "/var/lib/caddy/certs/imap.int.zandoodle.me.uk.crt";
        tls_server_key = "/var/lib/caddy/certs/imap.int.zandoodle.me.uk.key";
        virtdomains = "userid";
      };
    };
    postfix = {
      enable = true;
      enableSubmissions = true;
      settings = {
        main = {
          canonical_classes = "envelope_sender";
          canonical_maps = ''
            inline:{
              @compsoc-dev.com=@mail.compsoc-dev.com,
              @maxhearnden.me.uk=@mail.maxhearnden.me.uk,
              @maxhearnden.uk=@mail.maxhearnden.uk,
              @zandoodle.me.uk=@mail.zandoodle.me.uk
              }
          '';
          cyrus_sasl_config_path = "/etc/sasl2";
          disable_vrfy_command = true;
          local_login_sender_maps = "inline:{ mail-notification=failure-notification@zandoodle.me.uk }";
          myhostname = "mail.zandoodle.me.uk";
          mynetworks = [""];
          smtp_tls_ciphers = "high";
          smtp_tls_mandatory_ciphers = "high";
          smtp_tls_mandatory_protocols = ">=TLSv1.2";
          smtp_tls_protocols = ">=TLSv1.2";
          smtpd_sender_login_maps = ''
            inline:{
              @compsoc-dev.com=max@WORKSTATION.ZANDOODLE.ME.UK,
              @maxhearnden.me.uk=max@WORKSTATION.ZANDOODLE.ME.UK,
              @maxhearnden.uk=max@WORKSTATION.ZANDOODLE.ME.UK,
              @zandoodle.me.uk=max@WORKSTATION.ZANDOODLE.ME.UK,
              tp-link@zandoodle.me.uk=tp-link@zandoodle.me.uk
              }
          '';
          smtpd_sender_restrictions = "reject_sender_login_mismatch";
          smtpd_tls_ciphers = "high";
          smtpd_tls_mandatory_ciphers = "high";
          smtpd_tls_mandatory_protocols = ">=TLSv1.2";
          smtpd_tls_protocols = ">=TLSv1.2";
          tls_config_file = "/etc/postfix-ssl.conf";
          tls_config_name = "postfix";
          tls_high_cipherlist = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
          tls_preempt_cipherlist = true;
          tls_server_sni_maps = ''
            inline:{
              { mail.zandoodle.me.uk = /var/lib/caddy/certs/mail.zandoodle.me.uk.key /var/lib/caddy/certs/mail.zandoodle.me.uk.crt }
              { smtp.int.zandoodle.me.uk = /var/lib/caddy/certs/smtp.int.zandoodle.me.uk.key /var/lib/caddy/certs/smtp.int.zandoodle.me.uk.crt }
              }
          '';
          smtpd_tls_chain_files = [
            "/var/lib/caddy/certs/mail.zandoodle.me.uk.key"
            "/var/lib/caddy/certs/mail.zandoodle.me.uk.crt"
          ];
          virtual_alias_domains = "zandoodle.me.uk, maxhearnden.uk, maxhearnden.me.uk, compsoc-dev.com";
          virtual_alias_maps = ''
            inline:{
              @compsoc-dev.com=max@workstation.zandoodle.me.uk,
              @maxhearnden.me.uk=max@workstation.zandoodle.me.uk,
              @maxhearnden.uk=max@workstation.zandoodle.me.uk,
              @zandoodle.me.uk=max@workstation.zandoodle.me.uk
              }
          '';
          virtual_mailbox_domains = "workstation.zandoodle.me.uk";
          virtual_transport = "lmtp:unix:/run/cyrus/lmtp";
        };
      };
    };
    postfix-tlspol = {
      enable = true;
      settings.dns.address = "[::1]:55";
    };
    rspamd = {
      enable = true;
      locals = {
        "dmarc.conf".text = ''
          actions {
            reject = "reject";
            quarantine = "add header";
            softfail = "no action";
          }
        '';
        "dkim_signing.conf".text = ''
          allow_username_mismatch = true;
          path = "/var/lib/rspamd/dkim/$domain.$selector.key";
        '';
        "milter_headers.conf".text = ''
          extended_spam_headers = true;
          use = [ "x-spamd-bar", "authentication-results" ];
        '';
      };
      overrides."options.inc".text = "local_addrs = []"; # Don't consider any address local
      postfix.enable = true;
    };
  };
  systemd = {
    packages = [
      (pkgs.writeTextDir "lib/systemd/system/service.d/50-mailer.conf" ''
        [Unit]
        OnFailure=mail-notification@%N.service
      '')
      (pkgs.writeTextDir "lib/systemd/system/mail-notification@.service.d/50-mailer.conf" ''
      '')
    ];
    services = {
      cyrus-imap.serviceConfig.RuntimeDirectoryMode = "0750";
      "mail-notification@" = {
        serviceConfig = {
          BindPaths = "/var/lib/postfix";
          CapabilityBoundingSet = "";
          ExecStart = "/run/wrappers/bin/sendmail -t -f failure-notification@zandoodle.me.uk";
          Group = "mail-notification";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_NETLINK AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          StandardInputText = [
            "From: failure-notification@zandoodle.me.uk"
            "To: failure-notification-mail@zandoodle.me.uk"
            "Subject: Service %i failed"
          ];
          SystemCallArchitectures = "native";
          UMask = "077";
          User = "mail-notification";
        };
      };
    };
  };
  users = {
    groups.mail-notification = {};
    users = {
      cyrus.extraGroups = [ "caddy" ];
      mail-notification = {
        isSystemUser = true;
        group = "mail-notification";
      };
      postfix.extraGroups = [ "cyrus" ];
    };
  };
}
