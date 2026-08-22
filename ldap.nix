{ config, lib, pkgs, utils, ... }:

{
  environment = {
    etc = {
      "ldap.conf".text = ''
        URI ldap://local.zandoodle.me.uk
        SASL_MECH GSSAPI
        SASL_NOCANON yes
      '';
      "sasl2/slapd.conf".text = ''
        keytab: /var/lib/slapd/krb5.keytab
        mech_list: GSSAPI
        service_principal: *
      '';
      "slapd.ldif".text = ''
        dn: cn=config
        objectClass: olcGlobal
        cn: config
        olcSaslHost: local.zandoodle.me.uk
        olcTLSCertificateFile: /var/lib/caddy/certs/ldap.zandoodle.me.uk.crt
        olcTLSCertificateKeyFile: /var/lib/caddy/certs/ldap.zandoodle.me.uk.key
        olcTLSCipherSuite: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305

        dn: cn=schema,cn=config
        objectClass: olcSchemaConfig
        cn: schema

        include: file://${pkgs.openldap}/etc/schema/core.ldif

        dn: olcDatabase=frontend,cn=config
        objectClass: olcDatabaseConfig
        objectClass: olcFrontendConfig
        olcDatabase: frontend
        olcRootDN: uid=max@WORKSTATION.ZANDOODLE.ME.UK,cn=gssapi,cn=auth

        dn: olcDatabase=config,cn=config
        objectClass: olcDatabaseConfig
        olcDatabase: config
        olcRootDN: uid=max@WORKSTATION.ZANDOODLE.ME.UK,cn=gssapi,cn=auth

        dn: olcDatabase=mdb,cn=config
        objectClass: olcDatabaseConfig
        objectClass: olcMdbConfig
        olcDatabase: mdb
        olcDbMaxSize: 1073741824
        olcSuffix: dc=zandoodle,dc=me,dc=uk
        olcDbDirectory: /var/lib/slapd
        olcDbIndex: objectClass eq
        olcRootDN: uid=max@WORKSTATION.ZANDOODLE.ME.UK,cn=gssapi,cn=auth
      '';
    };
    systemPackages = [pkgs.openldap];
  };
  services.caddy.virtualHosts."ldap.zandoodle.me.uk".extraConfig = ''
    tls {
      issuer acme {
        dns_challenge_override_domain _acme-challenge.zandoodle.me.uk
        profile shortlived
      }
    }

    abort
  '';
  systemd = {
    services = {
      slapd = {
        confinement.enable = true;
        environment.SASL_CONF_PATH = "%E/sasl2";
        preStart = ''
          ${lib.getExe' pkgs.coreutils "rm"} -r /etc/slapd.d/* || true
          ${lib.getExe' pkgs.openldap "slapadd"} -n 0 -l ${
              config.environment.etc."slapd.ldif".source
            } -F /etc/slapd.d
        '';
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_BIND_SERVICE";
          BindReadOnlyPaths = [
            "${config.environment.etc."sasl2/slapd.conf".source}:/etc/sasl2/slapd.conf"
            "${config.environment.etc."krb5.conf".source}:/etc/krb5.conf"
            "/var/lib/caddy/certs"
          ];
          CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
          ConfigurationDirectory = "slapd.d";
          StateDirectory = "slapd";
          ExecStart = utils.escapeSystemdExecArgs [
            "${pkgs.openldap}/libexec/slapd"
            "-d"
            "0"
            "-F"
            "/etc/slapd.d"
            "-h"
            "ldap:/// ldaps:/// ldapi://%2frun%2fldap%2fldap.sock"
          ];
          Group = "slapd";
          NoNewPrivileges = true;
          PrivateUsers = lib.mkForce false;
          RuntimeDirectory = "ldap";
          User = "slapd";
        };
        wantedBy = [ "multi-user.target" ];
      };
    };
    tmpfiles.rules = [
      "d /etc/slapd.d 755 slapd slapd"
    ];
  };
  users = {
    groups.slapd = {};
    users.slapd = {
      extraGroups = [ "caddy" ];
      group = "slapd";
      isSystemUser = true;
    };
  };
}
