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

fn main() {
    let options = get_options();

    // 引数を解析
    let pubkey_values = options.values_of("publickey").unwrap(); // required
    let threshold = options.value_of("threshold").unwrap(); // required
    let privkey_value = options.value_of("privatekey"); // required
    let pubkey_list: Vec<PublicKey> = get_public_keys_from_options(pubkey_values).unwrap();
    let private_key = PrivateKey::from_wif(privkey_value.unwrap()).unwrap();
    let threshold: u32 = threshold.parse().unwrap();

    validate_options(&pubkey_list, &private_key, &threshold).unwrap();
    let params = NodeParameters { pubkey_list, threshold, private_key };
    let con = RedisManager::new();
    let node = &mut SignerNode::new(con, params);

    println!("node start.");
    node.start();
}


/// command example:
/// ./target/debug/node -p=03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc -p=02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900 -p=02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e --privatekey=cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA -t 2
fn get_options() -> ArgMatches<'static> {
    App::new("node")
        .about("Tapyrus siner node")
        .arg(Arg::with_name("publickey")
            .short("p")
            .long("publickey")
            .value_name("PUBKEY")
            .multiple(true)
            .help("Tapyrus signer public key. not need '0x' prefix. example: 03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc")
            .required(true))
        .arg(Arg::with_name("threshold")
            .short("t")
            .long("threshold")
            .value_name("NUM")
            .help("The threshold of enough signer. it must be less than specified public keys.")
            .required(true))
        .arg(Arg::with_name("privatekey")
            .long("privatekey")
            .value_name("PRIVATE_KEY")
            .help("The PrivateKey of this signer node. WIF format.")
            .required(true)).get_matches()
}

fn get_public_keys_from_options(keyargs: Values) -> Result<Vec<PublicKey>, bitcoin::consensus::encode::Error> {
    keyargs.map(|key| {
        PublicKey::from_str(key)
    }).collect()
}

fn validate_options(public_keys: &Vec<PublicKey>, private_key: &PrivateKey, threshold: &u32) -> Result<(), tapyrus_siner::errors::Error> {
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
