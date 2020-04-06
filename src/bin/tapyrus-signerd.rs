// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

extern crate bitcoin;
extern crate clap;
extern crate daemonize;
extern crate env_logger;
extern crate log;
extern crate redis;
extern crate tapyrus_signer;

use bitcoin::PublicKey;

use daemonize::Daemonize;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tapyrus_signer::command_args::{CommandArgs, RedisConfig, RpcConfig};
use tapyrus_signer::crypto::vss::Vss;
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
    validate_options(
        &signer_config.threshold(),
        &signer_config.public_key(),
        &signer_config.node_vss(),
    )
    .unwrap();

    let con = connect_signer_network(configs.redis_config());
    let rpc = connect_rpc(configs.rpc_config());

    let node_vss = signer_config.node_vss();
    let public_keys: Vec<PublicKey> = node_vss
        .iter()
        .map(|vss| vss.sender_public_key.clone())
        .collect();

    // TODO: set federations to NodeParameters
    let _federations = load_federations(
        &signer_config.public_key(),
        signer_config.federations_file(),
    );

    let params = NodeParameters::new(
        signer_config.to_address(),
        public_keys,
        signer_config.threshold(),
        signer_config.public_key(),
        node_vss,
        rpc,
        round_duration,
        general_config.skip_waiting_ibd(),
    );

    // Verify share
    params
        .verify_nodevss()
        .expect("The nodevss has invalid vss");

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

fn validate_options(
    threshold: &u8,
    public_key: &PublicKey,
    node_vss: &Vec<Vss>,
) -> Result<(), tapyrus_signer::errors::Error> {
    if node_vss.len() < *threshold as usize {
        let error_msg = format!(
            "Not enough number of node_vss. node_vss.len: {}, threshold: {}",
            node_vss.len(),
            threshold
        );
        return Err(tapyrus_signer::errors::Error::InvalidArgs(error_msg));
    }

    match node_vss
        .iter()
        .find(|vss| vss.sender_public_key == *public_key)
    {
        Some(_) => (),
        None => {
            return Err(tapyrus_signer::errors::Error::InvalidArgs(
                "The node_vss should include vss that sender is own public key.".to_string(),
            ));
        }
    }

    match node_vss
        .iter()
        .find(|vss| vss.receiver_public_key != *public_key)
    {
        Some(_) => {
            return Err(tapyrus_signer::errors::Error::InvalidArgs(
                "The receiver_public_key in node_vss should be own public key.".to_string(),
            ))
        }
        None => (),
    }

    // Check the commitment length equals to threshold
    for vss in node_vss {
        if vss.positive_commitments.len() != *threshold as usize
            || vss.negative_commitments.len() != *threshold as usize
        {
            return Err(tapyrus_signer::errors::Error::InvalidArgs(
                format!(
                    "Count of commitments in a vss should be same with threshold. vss: {}",
                    vss
                )
                .to_string(),
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
    use crate::{connect_rpc, connect_signer_network, load_federations, validate_options};
    use bitcoin::PublicKey;
    use std::path::Path;
    use std::str::FromStr;
    use tapyrus_signer::command_args::{RedisConfig, RpcConfig};
    use tapyrus_signer::crypto::vss::Vss;

    fn valid_signer_config() -> (u8, PublicKey, Vec<Vss>) {
        let threshold = 2;
        let public_key = PublicKey::from_str(
            "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e",
        )
        .unwrap();
        let node_vss = vec![
            Vss::from_str("02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0002785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e12ab6cc10390ee6e31985e52e7d5701bed4c265dfc899cac07bc9c608ab02a7409a4a4323b8563e835078e4fe631d102951360ce55c4ffe29e487e01d37ab919242d0245961b2aee967d84f45d2d1b5282584158e3b2235354342fe8264f3b93ab1bc68a8c3c15615080272d25661be167deb98c0f1a9c0e089e07f6ee978b0a785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5eed54933efc6f1191ce67a1ad182a8fe412b3d9a203766353f843639e754fd1bbc019a3ebb7d4a3ee41f209f1abc1019f69cffad1a911c85acad02765f5cebda61c64bb52aceeee1b5bd13377d596cc8dcc3a951bf83d81695c6d5e3936a459302852fa65686f009b250bcfb3c584dc65248339544d9499287b73a5c8a7c862fc").unwrap(),
            Vss::from_str("02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90002785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0002ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b90015ea9fee96aed6d9c0fc2fbe0bd1883dee223b3200246ff1e21976bdbc9a0fc87acdff559ec5caba396f7245eacf05d2e743d6b66bf4e3c47d82bbf6bd2b785db087a541af5f0e3a14fcc2038837668f186d32321780fbe927a38ac1cee182eabcae4e096a862e064d26acca76a57bf32381bd646435636fffa84125298a83f7ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900ea156011695129263f03d041f42e77c211ddc4cdffdb900e1de689414365ec6761d79d99fbd91390deadae9e66a7208bd8ffd1cfd14ffa2d037398ca420ff824435828ceb214c1f32bb9e353654225cd6d2d377a0903a27a0de1474552ade7b49b91767522d7f1b5118bd11ec5f3820cd0c4609ccc47d42a45fab84080144d3a").unwrap(),
            Vss::from_str("03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e0002831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc36efd8a52e2a27a50650b7e1f7db835c1f7fe5f7e587fb43e0009068b96d6ed3c3b1bc5b99b1ae4b88551a94ee8e1f39e64ecdb77f7c28c11b22474bb76c353eeec7dd7dea0fa23f9d1f8e61516a064f054d50b5c39eae42bf5800eed6f154887e6d3ed5cf16a40892c12b10668a10e85339b9884466f7a97fc49794d624a9c3831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafcc910275ad1d5d85af9af481e08247ca3e0801a081a7804bc1fff6f9646928d5c7f76aada955441f21ceebeccde4b7a008d1ef5ad69af1d5ce15db632b0ba8afac331a22efff9196577be2e6e58da8db0b5cbd3350046c2a699eb6735cc11770c55b6484c86d6354fa39ed860af28a511795800da0af0297766a521cba4e13dd2").unwrap(),
        ];

        (threshold, public_key, node_vss)
    }

    #[test]
    fn test_validate_options() {
        let (threshold, public_key, node_vss) = valid_signer_config();
        assert!(validate_options(&threshold, &public_key, &node_vss).is_ok());
    }

    #[test]
    #[should_panic(expected = "Not enough number of node_vss.")]
    fn test_validate_options_less_count_of_node_vss() {
        let (threshold, public_key, node_vss) = valid_signer_config();
        let node_vss = node_vss.into_iter().take(1).collect();
        validate_options(&threshold, &public_key, &node_vss).unwrap();
    }

    #[test]
    #[should_panic(expected = "The node_vss should include vss that sender is own public key.")]
    fn test_validate_options_no_my_origin_vss() {
        let (threshold, public_key, node_vss) = valid_signer_config();

        let node_vss = node_vss
            .into_iter()
            .map(|mut vss| {
                if vss.sender_public_key == public_key {
                    vss.sender_public_key = PublicKey::from_str(
                        "0381c5e2983561a2ba3b89d8d746e402b6ec351d025f8d2a8eae50a3f018d8ae20",
                    )
                    .unwrap()
                }
                vss
            })
            .collect();
        validate_options(&threshold, &public_key, &node_vss).unwrap();
    }

    #[test]
    #[should_panic(expected = "The receiver_public_key in node_vss should be own public key.")]
    fn test_validate_options_node_vss_includes_different_receiver() {
        let (threshold, public_key, mut node_vss) = valid_signer_config();
        node_vss[2].receiver_public_key = PublicKey::from_str(
            "0381c5e2983561a2ba3b89d8d746e402b6ec351d025f8d2a8eae50a3f018d8ae20",
        )
        .unwrap();
        validate_options(&threshold, &public_key, &node_vss).unwrap();
    }

    #[test]
    #[should_panic(expected = "Count of commitments in a vss should be same with threshold.")]
    fn test_validate_options_node_vss_has_invalid_count_of_commitments() {
        let (threshold, public_key, mut node_vss) = valid_signer_config();
        node_vss[0].positive_commitments.drain(1..);
        validate_options(&threshold, &public_key, &node_vss).unwrap();
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

    #[test]
    fn test_load_federations() {
        let pubkey = PublicKey::from_str(
            "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations.toml");
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
        expected = "federations_file: Invalid Federation at 0 height. message: The nodevss has wrong vss which has wrong number of commitments."
    )]
    fn test_load_federations_has_invalid_federation() {
        let pubkey = PublicKey::from_str(
            "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations_has_invalid_federation.toml");
        load_federations(&pubkey, path);
    }

    #[test]
    #[should_panic(
        expected = "federations_file: Invalid TOML format. missing field `threshold` for key `federation` at line 12 column 1"
    )]
    fn test_load_federations_invalid_toml_format() {
        let pubkey = PublicKey::from_str(
            "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
        )
        .unwrap();

        let path = Path::new("tests/resources/federations_invalid_toml_format.toml");
        load_federations(&pubkey, path);
    }
}
