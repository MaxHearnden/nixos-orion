{ config, inputs, lib, pkgs, ... }:

let
  nixos-kexec = pkgs.writeShellApplication {
    name = "nixos-kexec";
    text = lib.strings.fileContents "${inputs.nixos-kexec}/nixos-kexec";
  };
in

{
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
  systemd = {
    services = {
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
    };
    tmpfiles.rules = [
      "d /nix/var/nix/builds 755 root root 7d"
      "A /nix/var/nix/profiles - - - - u:nix-gc:rwx,d:u:nix-gc:rwx,m::rwx,d:m::rwx,g::rx,d:g::rx"
    ];
  };
  users = {
    groups.nix-gc = {};
    users.nix-gc = {
      isSystemUser = true;
      group = "nix-gc";
    };
  };
}
