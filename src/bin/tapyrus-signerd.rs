// Copyright (c) 2019 Chaintope Inc.

extern crate clap;
extern crate daemonize;
extern crate env_logger;
extern crate log;
extern crate redis;
extern crate tapyrus;
extern crate tapyrus_signer;

use tapyrus::PublicKey;

use daemonize::Daemonize;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tapyrus_signer::command_args::{CommandArgs, RedisConfig, RpcConfig};
use tapyrus_signer::federation::Federations;
use tapyrus_signer::net::{ConnectionManager, RedisManager};
use tapyrus_signer::rpc::Rpc;
use tapyrus_signer::signer_node::{NodeParameters, SignerNode};
use tapyrus_signer::util::{set_stop_signal_handler, signal_to_string};

/// This command is for launch tapyrus-signer-node.
fn main() {
    start_unix_signal_handling();

    let configs = CommandArgs::new().unwrap();

    let general_config = configs.general_config();

    if general_config.daemon() {
        daemonize(general_config.pid(), general_config.log_file());
    }

    let log_level = general_config.log_level();
    let is_quiet = general_config.log_quiet();
    let round_duration = general_config.round_duration();

    if !is_quiet {
        let env_value = format!("tapyrus_signer={},node={}", log_level, log_level);
        std::env::set_var("RUST_LOG", env_value);
        env_logger::init();
    }

    let signer_config = configs.signer_config();

    let con = connect_signer_network(configs.redis_config());
    let rpc = connect_rpc(configs.rpc_config());

    let federations = load_federations(
        &signer_config.public_key(),
        signer_config.federations_file(),
    );

    let params = NodeParameters::new(
        signer_config.to_address(),
        signer_config.public_key(),
        rpc,
        round_duration,
        general_config.round_limit(),
        general_config.skip_waiting_ibd(),
        federations,
    );

    let node = &mut SignerNode::new(con, params);
    node.start();
}

fn daemonize(pid: &str, log_file: &str) {
    println!("Start Tapyrus Signer Daemon. pid file: {}", pid);
    let stdout = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_file)
        .expect(&format!("Couldn't open {}", log_file));

    let stderr = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_file)
        .expect(&format!("Couldn't open {}", log_file));

    let daemonize = Daemonize::new().pid_file(pid).stdout(stdout).stderr(stderr);

    match daemonize.start() {
        Ok(_) => println!("Success, daemonized"),
        Err(e) => eprintln!("Error, {}", e),
    }
}

fn connect_rpc(rpc_config: RpcConfig) -> Rpc {
    let url = format!("http://{}:{}", rpc_config.host(), rpc_config.port());
    let user = rpc_config.user_name().map(str::to_string);
    let pass = rpc_config.password().map(str::to_string);
    let rpc = tapyrus_signer::rpc::Rpc::new(&url, user.clone(), pass);
    rpc.test_connection().expect(&format!(
        "Tapyrus Core RPC connection failed. Please confirm RPC connection info. url: {}, user: '{}' ,",
        url,
        user.unwrap_or("".to_string())
    ));
    rpc
}

fn connect_signer_network(rc: RedisConfig) -> impl ConnectionManager {
    let redis_manager = RedisManager::new(rc.host().to_string(), rc.port().to_string());
    redis_manager
        .test_connection()
        .expect("Failed to connect redis. Please confirm redis connection info");
    redis_manager
}

/// Handle unix signal
/// If the process got stop signals, it puts log and exit process.
fn start_unix_signal_handling() {
    let _ = std::thread::spawn(|| {
        // Add signal handler
        let unix_stop_signal_handler =
            set_stop_signal_handler().expect("Failed to register signal handler.");

        loop {
            // Unix Signal handler
            match unix_stop_signal_handler.load(Ordering::Relaxed) {
                0 => {}
                signal => {
                    log::info!("Signer Node was stopped by {}", signal_to_string(signal));
                    std::process::exit(0);
                }
            }

            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

fn load_federations(pubkey: &PublicKey, path: &Path) -> Federations {
    let federations_toml = std::fs::read_to_string(path).expect(&format!(
        "Can't open federations_file. path: {:?} Error",
        path
    ));
    match Federations::from_pubkey_and_toml(pubkey, &federations_toml) {
        Ok(r) => r,
        Err(tapyrus_signer::errors::Error::InvalidTomlFormat(e)) => {
            panic!("federations_file: Invalid TOML format. {}", e);
        }
        Err(tapyrus_signer::errors::Error::InvalidFederation(Some(height), m)) => {
            panic!(
                "federations_file: Invalid Federation at {} height. message: {}",
                height, m
            );
        }
        Err(tapyrus_signer::errors::Error::InvalidFederation(None, m)) => {
            panic!("federations_file: Invalid. message: {}", m);
        }
        Err(e) => {
            panic!("federations_file: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{connect_rpc, connect_signer_network, load_federations};
    use std::path::Path;
    use std::str::FromStr;
    use tapyrus::PublicKey;
    use tapyrus_signer::command_args::{RedisConfig, RpcConfig};

    #[test]
    #[should_panic(
        expected = "Tapyrus Core RPC connection failed. Please confirm RPC connection info. url: http://127.0.0.1:9999, user: '' "
    )]
    fn test_connect_rpc() {
        use tapyrus_signer::command_args::RpcCommandArgs;
        let config = RpcConfig {
            command_args: RpcCommandArgs {
                host: Some("127.0.0.1"),
                port: Some("9999"),
                username: None,
                password: None,
            },
            toml_config: None,
        };

        connect_rpc(config);
    }

    #[test]
    #[should_panic(expected = "Failed to connect redis. Please confirm redis connection info")]
    fn test_connect_signer_network() {
        use tapyrus_signer::command_args::RedisCommandArgs;
        // face redis config
        let config = RedisConfig {
            command_args: RedisCommandArgs {
                host: Some("127.0.0.1"),
                port: Some("9999"),
            },
            toml_config: None,
        };

        connect_signer_network(config);
    }

    #[test]
    fn test_load_federations() {
        let pubkey = PublicKey::from_str(
            "0315d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c9",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations.toml");
        let federations = load_federations(&pubkey, path);

        assert_eq!(federations.len(), 2);
    }

    #[test]
    fn test_load_federations_threshold_change() {
        let pubkey = PublicKey::from_str(
            "0315d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c9",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations_threshold_change.toml");
        let federations = load_federations(&pubkey, path);

        assert_eq!(federations.len(), 2);
    }

    #[test]
    #[should_panic(expected = "Can't open federations_file. path: \"/foo/bar/no_exist_file.toml\"")]
    fn test_load_federations_invalid_file_path() {
        let pubkey = PublicKey::from_str(
            "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
        )
        .unwrap();

        let path = Path::new("/foo/bar/no_exist_file.toml");
        load_federations(&pubkey, path);
    }

    #[test]
    #[should_panic(
        expected = "federations_file: Invalid Federation at 20 height. message: The nodevss has wrong vss which has wrong number of commitments."
    )]
    fn test_load_federations_has_invalid_federation() {
        let pubkey = PublicKey::from_str(
            "0315d137054b688717f7fe4bd22a1c886de7a07bf3beb041092fb79688306df3c9",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations_has_invalid_federation.toml");
        load_federations(&pubkey, path);
    }

    #[test]
    #[should_panic(
        expected = "federations_file: Invalid Federation at 100 height. message: No xfield in federation. Aggregated pubkey or max block size is expected"
    )]
    fn test_load_federations_invalid_toml_format() {
        let pubkey = PublicKey::from_str(
            "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations_invalid_toml_format.toml");
        load_federations(&pubkey, path);
    }

    #[test]
    fn test_load_federations_has_max_block_size() {
        let pubkey = PublicKey::from_str(
            "0302f5584e30d2ee32e772d04ff8ee1efc90a7a91ac5b7c4025da7a42a67d06a25",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations_has_max_block_size.toml");
        load_federations(&pubkey, path);
    }
}
