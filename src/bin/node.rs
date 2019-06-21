extern crate tapyrus_siner;
extern crate bitcoin;
extern crate log;
extern crate redis;
extern crate clap;

use clap::{App, Arg, Values, ArgMatches};
use bitcoin::{PrivateKey, PublicKey};
use tapyrus_siner::signer_node::{NodeParameters, SignerNode};
use std::str::FromStr;
use tapyrus_siner::net::RedisManager;

pub const OPTION_NAME_PUBLIC_KEY: &str = "publickey";
pub const OPTION_NAME_PRIVATE_KEY: &str = "privatekey";
pub const OPTION_NAME_THRESHOLD: &str = "threshold";
pub const OPTION_NAME_MASTER_FLAG: &str = "master_flag";
pub const OPTION_NAME_RPC_ENDPOINT_HOST: &str = "rpc_endpoint_host";
pub const OPTION_NAME_RPC_ENDPOINT_PORT: &str = "rpc_endpoint_port";
pub const OPTION_NAME_RPC_ENDPOINT_USER: &str = "rpc_endpoint_user";
pub const OPTION_NAME_RPC_ENDPOINT_PASS: &str = "rpc_endpoint_pass";

pub const OPTION_NAME_REDIS_HOST: &str = "redis_host";
pub const OPTION_NAME_REDIS_PORT: &str = "redis_port";

/// This command is for launch tapyrus-signer-node.
/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 2 --master
fn main() {
    let options = get_options();

    // 引数を解析
    let pubkey_values = options.values_of(OPTION_NAME_PUBLIC_KEY).unwrap(); // required
    let threshold = options.value_of(OPTION_NAME_THRESHOLD).unwrap(); // required
    let privkey_value = options.value_of(OPTION_NAME_PRIVATE_KEY); // required
    let pubkey_list: Vec<PublicKey> = get_public_keys_from_options(pubkey_values).unwrap();
    let private_key = PrivateKey::from_wif(privkey_value.unwrap()).unwrap();
    let threshold: u8 = threshold.parse().unwrap();

    validate_options(&pubkey_list, &private_key, &threshold).unwrap();
    let rpc = {
        let host = options.value_of(OPTION_NAME_RPC_ENDPOINT_HOST).unwrap_or_default();
        let port = options.value_of(OPTION_NAME_RPC_ENDPOINT_PORT).unwrap_or_default();
        let user = options.value_of(OPTION_NAME_RPC_ENDPOINT_USER).map(|v|v.to_string());
        let pass = options.value_of(OPTION_NAME_RPC_ENDPOINT_PASS).map(|v|v.to_string());

        tapyrus_siner::rpc::Rpc::new(format!("http://{}:{}", host, port), user, pass)
    };
    let params = NodeParameters::new(pubkey_list,  private_key, threshold, rpc, options.is_present(OPTION_NAME_MASTER_FLAG));
    let con = {
        let host = options.value_of(OPTION_NAME_REDIS_HOST).unwrap_or_default();
        let port = options.value_of(OPTION_NAME_REDIS_PORT).unwrap_or_default();
        RedisManager::new(host.to_string(), port.to_string())
    };
    let node = &mut SignerNode::new(con, params);

    node.start();
}


/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 2 --master
fn get_options() -> ArgMatches<'static> {
    App::new("node")
        .about("Tapyrus siner node")
        .arg(Arg::with_name(OPTION_NAME_PUBLIC_KEY)
            .short("p")
            .long("publickey")
            .value_name("PUBKEY")
            .multiple(true)
            .help("Tapyrus signer public key. not need '0x' prefix. example: 03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc")
            .required(true))
        .arg(Arg::with_name(OPTION_NAME_THRESHOLD)
            .short("t")
            .long("threshold")
            .value_name("NUM")
            .help("The threshold of enough signer. it must be less than specified public keys.")
            .required(true))
        .arg(Arg::with_name(OPTION_NAME_PRIVATE_KEY)
            .long("privatekey")
            .value_name("PRIVATE_KEY")
            .help("The PrivateKey of this signer node. WIF format.")
            .required(true))
        .arg(Arg::with_name(OPTION_NAME_MASTER_FLAG)
            .long("master")
            .help("Master Node Flag. If launch as Master node, then set this option."))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_HOST)
            .long("rpchost")
            .value_name("HOST_NAME or IP")
            .help("TapyrusCore RPC endpoint host.")
            .default_value("127.0.0.1"))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_PORT)
            .long("rpcport")
            .value_name("PORT")
            .help("TapyrusCore RPC endpoint port number. These are TapyrusCore default port, mainnet: 2377, testnet: 12377, regtest: 12381.")
            .default_value("2377"))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_USER)
            .long("rpcuser")
            .value_name("USER")
            .help("TapyrusCore RPC user name."))
        .arg(Arg::with_name(OPTION_NAME_RPC_ENDPOINT_PASS)
            .long("rpcpass")
            .value_name("PASS")
            .help("TapyrusCore RPC user password."))
        .arg(Arg::with_name(OPTION_NAME_REDIS_HOST)
            .long("redishost")
            .value_name("HOST_NAME or IP")
            .default_value("127.0.0.1")
            .help("Redis host."))
        .arg(Arg::with_name(OPTION_NAME_REDIS_PORT)
            .long("redisport")
            .value_name("PORT")
            .default_value("6379")
            .help("Redis port."))
        .get_matches()
}

fn get_public_keys_from_options(keyargs: Values) -> Result<Vec<PublicKey>, bitcoin::consensus::encode::Error> {
    keyargs.map(|key| {
        PublicKey::from_str(key)
    }).collect()
}

fn validate_options(public_keys: &Vec<PublicKey>, private_key: &PrivateKey, threshold: &u8) -> Result<(), tapyrus_siner::errors::Error> {
    if public_keys.len() < *threshold as usize {
        let error_msg = format!("Not enough number of public keys. publicKeys.len: {}, threshold: {}",
                                public_keys.len(), threshold);
        return Err(tapyrus_siner::errors::Error::InvalidArgs(error_msg));
    }
    let pubkey_from_private = private_key.public_key(&secp256k1::Secp256k1::new());
    match public_keys.iter().find(|&&p| p == pubkey_from_private) {
        Some(_) => {
            ()
        }
        None => {
            return Err(tapyrus_siner::errors::Error::InvalidArgs(
                "Private key is not pair of any one of Public key list.".to_string()));
        }
    }
    Ok(())
}

#[test]
#[should_panic(expected = "Not enough number of public keys. publicKeys.len:")]
fn test_validate_options_less_threshold() {
    let pubkey_list = vec![
        PublicKey::from_str("03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc").unwrap(),
    ];
    let threshold = 2;
    let private_key = PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();

    validate_options(&pubkey_list, &private_key, &threshold).unwrap();
}

#[test]
#[should_panic(expected = "Private key is not pair of any one of Public key list.")]
fn test_validate_options_no_pair() {
    let pubkey_list = vec![
        PublicKey::from_str("02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900").unwrap(),
        PublicKey::from_str("02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e").unwrap(),
    ];
    let threshold = 1;
    let private_key = PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();

    validate_options(&pubkey_list, &private_key, &threshold).unwrap();
}
