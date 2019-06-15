# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, lib, ... }:

{
  imports = [
		<nixpkgs/nixos/modules/virtualisation/virtualbox-image.nix>
  ];
  # Use the GRUB 2 boot loader.
  boot.loader.grub.enable = true;
  boot.loader.grub.version = 2;

  virtualbox.baseImageSize = 8 * 1024;
  virtualbox.vmName = "Roger Skyline 1";

  # Disable default autoResize of virtualbox-image
  fileSystems."/".autoResize = lib.mkForce false;

  boot.initrd.extraUtilsCommands = ''
    copy_bin_and_libs ${pkgs.e2fsprogs}/sbin/resize2fs
    copy_bin_and_libs ${pkgs.parted}/sbin/parted
  '';

  # Partition image to 4.2G
  boot.initrd.postDeviceCommands = ''
    resize2fs ${config.fileSystems."/".device} 4200M
    parted --script /dev/sda -- \
      rm 1 \
      mkpart primary ext4 1MiB 4301MiB
  '';

  # Copy configuration on first boot
  boot.postBootCommands = ''
    if ! [ -e /etc/nixos/configuration.nix ]; then
      cp ${./roger.nix} /etc/nixos/roger.nix
      cp ${./host.cert} /etc/nixos/host.cert
      cp ${./host.key} /etc/nixos/host.key
      ln -s /etc/nixos/roger.nix /etc/nixos/configuration.nix
    fi
    if ! [ -e /etc/crontab ]; then
      touch /etc/crontab
    fi
  '';

  services.openssh = {
    enable = true;
    permitRootLogin = "no";
    ports = [4222];
    passwordAuthentication = false;
  };

  services.netdata.enable = true;
  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    recommendedOptimisation = true;
    recommendedGzipSettings = true;
    virtualHosts."default" = {
      forceSSL = true;
      sslCertificate = ./host.cert;
      sslCertificateKey = ./host.key;
      locations."/" = {
        proxyPass = "http://localhost:19999";
      };
    };
  };

  # Local mail server
  services.postfix = {
    enable = true;
    destination = [config.networking.hostName "localhost"];
  };

  # Disable Name Service Cache daemon
  services.nscd.enable = false;

  # Auto upgrade
  system.autoUpgrade = {
    enable = true;
    channel = https://nixos.org/channels/nixos-19.03;
    dates = "Mon *-*-* 04:00:00";
  };
  # Start at boot
  systemd.services.nixos-upgrade.wantedBy = ["multi-user.target"];
  systemd.services.nixos-upgrade.after = ["network-online.target"];
  systemd.services.nixos-upgrade.serviceConfig.StandardOutput = "file:/var/log/update_script.log";

  # Crontab script
  systemd.services.watch-crontab = {
    description = "Watch Crontab";
    serviceConfig = {
      Type = "oneshot";
      User = "watch-crontab";
    };

    script = ''
      set +e
      diff=$(${pkgs.diffutils}/bin/diff ${/etc/crontab} /etc/crontab)
      if [ $? != 0 ]; then
        echo "$diff" | ${pkgs.mailutils}/bin/mail -s "Crontab Modified" root
      fi;
    '';
    startAt = "daily";
  };

  systemd.paths.watch-crontab = {
    # wantedBy = ["multi-user.target"];
    pathConfig = {
      PathModified = "/etc/crontab";
    };
  };

  users.users.watch-crontab = {
    home = "/var/empty";
  };


  services.fail2ban = {
    enable = true;
    jails.portscan = ''
      filter = portscan
      action = iptables-allports[name=portscan, protocol=tcp]
    '';
  };

  # NixOS Firewall log by default failed connection with prefix "refused connection: "
  # see https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/firewall.nix#L101
  environment.etc."fail2ban/filter.d/portscan.conf".text = ''
    [Definition]
    failregex = refused connection.* SRC=<HOST>
  '';

  users.extraUsers.david = {
    isNormalUser = true;
    home = "/home/david";
    extraGroups = [ "wheel"];
    hashedPassword = "$6$vj3yFZqw$/86mpLxHiGEhb7JHzrsbjwF3/9BPGVO2FxtJwLHClYYwHkWy66t8iY2BrSGVZ66T//Wr/vHAyykJ2UO6ADnDS/";
    shell = pkgs.fish;
    openssh.authorizedKeys.keys = ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCzPcq+TZteAJkQLccbp5Bx4jPtmV6EfG0WNC8LHd0I505GOz171Gi+3YPJ9hM0Ny9e5ZTmvaF1EaX4vwX1egG/tNOOr+PRvDcAvXOtEbI3Y4mdNg9vK+jXaNyEIduFvS/fZVqDKEDwTRR+8HMORwXXYzf9c3iZlC5XBv8Loimb7bz2VO7eMkVfiJNgRiut0qdFv0QQQUabTD0hgL2bsgBTpjM/vvJQ4aVcJO7YvUBSWe+djcFU9Bav/VcV8+Pbn6UDl45wq2pyiu0/qJfomWTtUBiL6upBWEFEADkTnpdlzTZ9W3kbkGbWTfzltDDkZgrpHm6U8AXfFPUQrUDBmw8QDZ2XXnb/h2ljIyNH0A0hpKQGsDFhv7xm9PJuIeBRXUws0+poVWt1hQhek2i4Qb0ib2JbYoHOi3YnUMK6z2ZAhCJQLi0A+SsQn28+CgAC9j5Exz4RoxvP5nSQG5jzUOdhmDbC4CVS406SI9nfrTDt1v5ZGiJDCYPvkO61U4VfSWofsitom7l+nWLpT/7FqOUz17uftFzjKqULmoVVSwB4w/XLpcOa6u0gqveJYAZmfAoTpY4TppCkUuaEs+EOONj9v3zOgn6oKLL3+oo/a6cxA9WnYHCReavDGeN4rVfpksjA8+EcnJZaQfXVlAeR5hTuF5DUk/h1lzpIidjQgoM7tw== dde-jesu@student.42.fr"];
  };

  networking = {
    hostName = "rs1";
    interfaces.enp0s3 = {
      ipv4.addresses = [{
        address = "10.13.254.252";
        prefixLength = 30;
      }];
      useDHCP = false;
    };
    defaultGateway = "10.13.254.254";
    nameservers = [ "9.9.9.9" "149.112.112.112" ];
    useNetworkd = true;
    firewall.allowedTCPPorts = [80 443];
 };

  programs.fish.enable = true;

  time.timeZone = "Europe/Paris";

  environment.systemPackages = with pkgs; [
    wget vim mailutils
  ];

  system.stateVersion = "19.03";
}
