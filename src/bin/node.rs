// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

extern crate bitcoin;
extern crate clap;
extern crate env_logger;
extern crate log;
extern crate redis;
extern crate tapyrus_signer;
extern crate daemonize;

use bitcoin::{PrivateKey, PublicKey};

use std::sync::atomic::Ordering;
use std::time::Duration;
use tapyrus_signer::command_args::{CommandArgs, RedisConfig, RpcConfig};
use tapyrus_signer::net::{ConnectionManager, RedisManager};
use tapyrus_signer::rpc::Rpc;
use tapyrus_signer::signer_node::{NodeParameters, SignerNode};
use tapyrus_signer::util::{set_stop_signal_handler, signal_to_string};
use daemonize::Daemonize;
use std::fs::File;

/// This command is for launch tapyrus-signer-node.
/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e -p=02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c -p=02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506 --privatekey=cTRkG8i8PP7imvryqQwcYm787WHRdMmUqBvi1Z456gHvVoKnJ9TK -t 3 --rpcport=12381 --rpcuser=user --rpcpass=pass --master
fn main() {
    start_unix_signal_handling();

    let configs = CommandArgs::new().unwrap();

    let general_config = configs.general_config();

    if general_config.daemon() {
        daemonize(
            general_config.pid()
        );
    }

    let log_level = general_config.log_level();
    let is_quiet = general_config.log_quiet();
    let round_duration = general_config.round_duration();
    let is_master = general_config.master();

    if !is_quiet {
        let env_value = format!("tapyrus_signer={},node={}", log_level, log_level);
        std::env::set_var("RUST_LOG", env_value);
        env_logger::init();
    }

    let signer_config = configs.signer_config();
    validate_options(
        &signer_config.public_keys(),
        &signer_config.private_key(),
        &signer_config.threshold(),
    )
    .unwrap();

    let con = connect_signer_network(configs.redis_config());
    let rpc = connect_rpc(configs.rpc_config());

    let params = NodeParameters::new(
        signer_config.to_address(),
        signer_config.public_keys(),
        signer_config.private_key(),
        signer_config.threshold(),
        rpc,
        is_master,
        round_duration,
        general_config.skip_waiting_ibd(),
    );
    let node = &mut SignerNode::new(con, params);
    node.start();
}

fn daemonize(pid: &str) {
    println!("Start Tapyrus Signer Daemon. pid file: {}", pid);

    let daemonize = Daemonize::new()
        .pid_file(pid);

    match daemonize.start() {
        Ok(_) => println!("Success, daemonized"),
        Err(e) => eprintln!("Error, {}", e),
    }
}

fn validate_options(
    public_keys: &Vec<PublicKey>,
    private_key: &PrivateKey,
    threshold: &u8,
) -> Result<(), tapyrus_signer::errors::Error> {
    if public_keys.len() < *threshold as usize {
        let error_msg = format!(
            "Not enough number of public keys. publicKeys.len: {}, threshold: {}",
            public_keys.len(),
            threshold
        );
        return Err(tapyrus_signer::errors::Error::InvalidArgs(error_msg));
    }
    let pubkey_from_private = private_key.public_key(&secp256k1::Secp256k1::new());
    match public_keys.iter().find(|&&p| p == pubkey_from_private) {
        Some(_) => (),
        None => {
            return Err(tapyrus_signer::errors::Error::InvalidArgs(
                "Private key is not pair of any one of Public key list.".to_string(),
            ));
        }
    }
    Ok(())
}

fn connect_rpc(rpc_config: RpcConfig) -> Rpc {
    let url = format!("http://{}:{}", rpc_config.host(), rpc_config.port());
    let user = rpc_config.user_name().map(str::to_string);
    let pass = rpc_config.password().map(str::to_string);
    let rpc = tapyrus_signer::rpc::Rpc::new(url.clone(), user.clone(), pass);
    rpc.test_connection().expect(&format!(
        "RPC connect failed. Please confirm RPC connection info. url: {}, user: '{}' ,",
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

#[test]
#[should_panic(expected = "Not enough number of public keys. publicKeys.len:")]
fn test_validate_options_less_threshold() {
    use std::str::FromStr;

    let pubkey_list = vec![PublicKey::from_str(
        "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc",
    )
    .unwrap()];
    let threshold = 2;
    let private_key =
        PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();

    validate_options(&pubkey_list, &private_key, &threshold).unwrap();
}

#[test]
#[should_panic(expected = "Private key is not pair of any one of Public key list.")]
fn test_validate_options_no_pair() {
    use std::str::FromStr;

    let pubkey_list = vec![
        PublicKey::from_str("02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900")
            .unwrap(),
        PublicKey::from_str("02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e")
            .unwrap(),
    ];
    let threshold = 1;
    let private_key =
        PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();

    validate_options(&pubkey_list, &private_key, &threshold).unwrap();
}

#[test]
#[should_panic(
    expected = "RPC connect failed. Please confirm RPC connection info. url: http://127.0.0.1:9999, user: '' "
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
