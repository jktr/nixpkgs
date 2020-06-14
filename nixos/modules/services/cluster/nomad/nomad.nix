{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.nomad;

  configFile = pkgs.writeText "nomad.json" (builtins.toJSON ({
    bind_addr = cfg.listenAddress;
    disable_update_check = true;
    server_join = { retry_join = cfg.servers; };
    server = {
      enabled = true;
      bootstrap_expect = lib.max 1 (lib.length cfg.servers);
    } // cfg.server.configOptions;
    client = {
      enabled = true;
    } // cfg.client.configOptions;
  } // lib.optionalAttrs (cfg.certFile != null && cfg.keyFile != null) {
    tls = {
      ca_file = cfg.caFile;
      cert_file = cfg.certFile;
      key_file = cfg.keyFile;
      http = true;
      rpc = true;
      verify_https_client = true;
      verify_server_hostname = true;
    };
  }));

  extraConfigFile = pkgs.writeText "nomad-extra.conf"
    (if(lib.isAttrs cfg.extraConfig)
     then (builtins.toJSON cfg.extraConfig)
     else cfg.extraConfig);
in
{
  options = {
    services.nomad.client = {
      enable = mkEnableOption ''
        Enable the Nomad agent's client role. May be combined
        with <option>services.nomad.server.enable</option>.
      '';

      configOptions = mkOption {
        type = types.attrs;
        default = {};
        description = ''
          Extra configuration to merge into the <literal>client<literal> stanza.
          See the <link xlink:href="https://www.nomadproject.io/docs/configuration/client/"><literal>client</literal></link> stanza documentation for details.
        '';
      };
    };

    services.nomad.server = {
      enable = mkEnableOption ''
        Enable the Nomad agent's server role. May be combined
        with <option>services.nomad.client.enable</option>.
      '';

      initialGossipKeyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Path to file containing the server's initial gossip encryption key.
          Providing a file here will permanently enable server gossip encryption
          for this agent. Subsequent changes to this option are ignored.
          See the documentation for nomad's <link xlink:href="https://www.nomadproject.io/docs/configuration/server/#encrypt"><literal>encrypt</literal></link> directive for details.
        '';
      };

      configOptions = mkOption {
        type = types.attrs;
        default = {};
        description = ''
          Extra configuration to merge into the <literal>server</literal> stanza.
          See the <link xlink:href="https://www.nomadproject.io/docs/configuration/server/"><literal>server</literal></link> stanza documentation for details.
        '';
      };
    };

    services.nomad = {
      package = mkOption {
        type = types.package;
        default = pkgs.nomad;
        defaultText = "pkgs.nomad";
        description = "The Nomad package to use.";
      };

      listenAddress = mkOption {
        type = types.str;
        default = "0.0.0.0";
        description = ''
          Address to bind. Equivalent to nomad's
          <link xlink:href="https://www.nomadproject.io/docs/configuration/#bind_addr"><literal>bind_addr</literal></link> directive.
          You may need to set the <link xlink:href="https://www.nomadproject.io/docs/configuration/#advertise"><literal>advertise</literal> addresses</link> as well.
        '';
      };

      servers = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          List of servers to join on startup. Equivalent to nomad's
          <link xlink:href="https://www.nomadproject.io/docs/configuration/server_join/#retry_join"><literal>server_join.retry_join</literal></link> directive.
        '';
      };

      caFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/path/to/your/ca-cert.pem";
        description = "TLS CA cert file.";
      };

      certFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/path/to/your/cert.pem";
        description = ''
          TLS certificate file. TLS will be disabled unless this option is set.
          Please note that you should not use certificates issued by a public
          CA (like Let's Encrypt) here and that Nomad imposes constraints
          on the certificate's common names.
          See the <link xlink:href="https://learn.hashicorp.com/nomad/transport-security/enable-tls">Nomad TLS Guide</link> for details.
        '';
      };

      keyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/path/to/your/key.pem";
        description = "TLS private key file. TLS will be disabled unless this option is set.";
      };

      user = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          User account under which nomad runs. Uses systemd's DynamicUser if unset.
          Note that some task drivers may require the nomad agent to run as root.
        '';
      };

      extraConfig = mkOption {
        type = types.nullOr (types.oneOf [types.lines types.attrs]);
        default = null;
        description = "Additional nomad configuration (as HCL or a nix attribute set).";
      };
    };
  };

  config = mkIf (cfg.client.enable || cfg.server.enable) {
    environment.systemPackages = [ cfg.package ];
    systemd.services.nomad = {
      description = "Nomad workload orchestrator agent";
      documentation = ["https://www.nomadproject.io/docs/"];

      wantedBy = ["multi-user.target"];
      after = [ "network.target" ]
              ++ optional (config.services.consul.enable) "consul.service"
              ++ optional (config.services.vault.enable) "vault.service";

      # needed for network fingerprinting logic
      path = [ pkgs.iproute ];

      serviceConfig =
      let
        agentOpts = [ "-data-dir" "%S/nomad" "-config" "${configFile}" ]
          ++ (optional (cfg.extraConfig != null) [ "-config" "${extraConfigFile}" ]);
      in
      {
        DynamicUser = (cfg.user == null);
        ExecStart = toString (["${cfg.package}/bin/nomad" "agent"] ++ agentOpts);
        ExecReload = "${pkgs.coreutils}/bin/kill -SIGHUP $MAINPID";
        StateDirectory = "nomad";
      } // lib.optionalAttrs (cfg.user != null) {
        User = cfg.user;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectSystem = "full";
        ProtectHome = "read-only";
        NoNewPrivileges = true;
      };
    } // lib.optionalAttrs (cfg.server.initialGossipKeyFile != null) {
      preStart = ''
        # https://www.serf.io/docs/agent/options.html#example-keyring-file
        cd /var/lib/nomad
        mkdir -p server
        if ! [ -f server/serf.keyring ]; then
          ${pkgs.jq}/bin/jq --raw-input '[tostring]' \
            < "${cfg.server.initialGossipKeyFile}" \
            > server/serf.keyring
        fi
      '';
    };
  };
}
