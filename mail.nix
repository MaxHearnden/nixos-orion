{ lib, pkgs, ... }: {
  environment.etc = {
    "postfix-ssl.conf".text = ''
      postfix = postfix_settings

      [postfix_settings]
      ssl_conf = postfix_ssl_settings

      [postfix_ssl_settings]
      system_default = baseline_postfix_settings

      [baseline_postfix_settings]
      SignatureAlgorithms = ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512
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
          }
        }

        abort
      '';
      "smtp.int.zandoodle.me.uk".extraConfig = ''
        tls {
          issuer acme {
            dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
          }
        }

        abort
      '';
      "mail.zandoodle.me.uk".extraConfig = ''
        tls {
          issuer acme {
            dns_challenge_override_domain mail._acme-challenge.zandoodle.me.uk
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
            override_domain mail._acme-challenge.zandoodle.me.uk
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
          override_domain mail._acme-challenge.zandoodle.me.uk
        }
        tls.loader.acme smtp {
          agreed
          challenge dns-01
          dns rfc2136 {
            import /run/credentials/maddy.service/tsig.conf
            server "[::1]:54"
          }
          hostname smtp.zandoodle.me.uk
          override_domain mail._acme-challenge.zandoodle.me.uk
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

        # smtp tcp://0.0.0.0:25 {
        #   limits {
        #     all rate 20 1s
        #     all concurrency 10
        #   }

        #   dmarc yes
        #   check {
        #     require_mx_record
        #     dkim
        #     spf
        #   }

        #   source $(local_domains) {
        #     reject 501 5.1.8 "Use Submission for outgoing SMTP"
        #   }

        #   default_source {
        #     destination $(local_domains) {
        #       deliver_to &local_routing
        #     }

        #     default_destination {
        #       reject
        #     }
        #   }
        # }

        submission tcp://0.0.0.0:587 {
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
    postfix = {
      enable = true;
      enableSubmissions = true;
      settings = {
        main = {
          canonical_classes = "envelope_sender";
          canonical_maps =
            "inline:{@zandoodle.me.uk=@mail.zandoodle.me.uk,@compsoc-dev.com=@mail.compsoc-dev.com}";
          cyrus_sasl_config_path = "/etc/sasl2";
          local_login_sender_maps = "inline:{ mail-notification=failure-notification@zandoodle.me.uk }";
          myhostname = "mail.zandoodle.me.uk";
          mynetworks = [""];
          smtp_tls_ciphers = "high";
          smtp_tls_mandatory_ciphers = "high";
          smtp_tls_mandatory_protocols = ">=TLSv1.2";
          smtp_tls_protocols = ">=TLSv1.2";
          smtpd_sender_login_maps = ''
            inline:{
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
          virtual_alias_domains = "zandoodle.me.uk, compsoc-dev.com";
          virtual_alias_maps = ''
            inline:{
              @compsoc-dev.com=max@workstation.zandoodle.me.uk,
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
      maddy.serviceConfig = {
        LoadCredential = "tsig.conf:/run/keymgr/maddy-config";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        ProcSubset = "pid";
        ProtectKernelLogs = true;
        ProtectProc = "invisible";
        RemoveIPC = true;
        SystemCallArchitectures = "native";
      };
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
