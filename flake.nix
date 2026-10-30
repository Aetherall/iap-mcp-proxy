{
  description = "stdio MCP proxy for MCP servers behind Google Cloud IAP";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = self.shortRev or self.dirtyShortRev or "dev";
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.buildGoModule {
          pname = "iap-mcp-proxy";
          inherit version;
          src = self;
          vendorHash = "sha256-+Xqx4zMmJgUF18n7unFSlLcklyTiPx+/YOw+z4Epy/U=";
          subPackages = [ "cmd/iap-mcp-proxy" ];
          env.CGO_ENABLED = "0";
          # the tests listen on 127.0.0.1, which the macOS sandbox blocks by default
          __darwinAllowLocalNetworking = true;
          ldflags = [ "-s" "-w" "-X main.version=${version}" ];
          meta = {
            description = "stdio MCP proxy for MCP servers behind Google Cloud IAP";
            homepage = "https://github.com/Aetherall/iap-mcp-proxy";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "iap-mcp-proxy";
          };
        };
      });
    };
}
