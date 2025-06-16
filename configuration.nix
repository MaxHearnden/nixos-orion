{ config, pkgs, ... }: {
  boot = {
    kernelPackages = pkgs.linuxPackages_latest;
    loader.systemd-boot.enable = true;
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
  networking.hostName = "orion";
  nix = {
    gc = {
      automatic = true;
      options = "--delete-older-than 7d";
    };
    settings = {
      experimental-features = "nix-command flakes";
      keep-outputs = true;
    };
  };
  programs = {
    git = {
      enable = true;
      config = {
        init.defaultBranch = "main";
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
        '';
        packages.nix.start = with pkgs.vimPlugins; [ vim-nix ];
      };
      defaultEditor = true;
      enable = true;
    };
  };
  services = {
    knot = {
      enable = true;
    };
    openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };
    xserver = {
      enable = true;
      desktopManager.gnome.enable = true;
      displayManager.gdm = {
        autoSuspend = false;
        enable = true;
      };
    };
  };
  system = {
    autoUpgrade = {
      allowReboot = true;
      enable = true;
      flags = [ "--no-write-lock-file" ];
      flake = "git+file:///home/max/nixos-config";
    };
    stateVersion = "24.11";
  };
  systemd.shutdownRamfs.enable = false;
  users.users.max = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmioGtxIY2vgxZi5czG/tIkSKga/91RDyTsNtc6fU3D max@max-nixos-pc"
    ];
    packages = with pkgs; [
      btop
      htop
    ];
  };
}
