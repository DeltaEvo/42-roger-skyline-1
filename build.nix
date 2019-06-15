(import <nixpkgs/nixos/lib/eval-config.nix> {
	system = "x86_64-linux";
  modules = [
		./roger.nix
	];
}).config.system.build.virtualBoxOVA