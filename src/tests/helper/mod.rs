use crate::net::{BlockGenerationRoundMessageType, Message, MessageType, SignerID};
use crate::tests::helper::keys::TEST_KEYS;
use bitcoin::{Address, PrivateKey};

pub mod blocks;
pub mod keys;
pub mod net;
pub mod node_parameters_builder;
pub mod node_state_builder;
pub mod rpc;

pub fn enable_log(log_level: Option<log::Level>) {
    if let Some(level) = log_level {
        std::env::set_var("RUST_LOG", level.to_string());
    } else {
        std::env::set_var("RUST_LOG", "TRACE");
    }

    let _ = env_logger::builder().is_test(true).try_init();
}

pub fn create_message() -> Message {
    let signer_id = SignerID::new(TEST_KEYS.pubkeys()[0]);
    Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Roundfailure,
        ),
        sender_id: signer_id,
        receiver_id: None,
    }
}

pub fn address(private_key: &PrivateKey) -> Address {
    let secp = secp256k1::Secp256k1::new();
    let self_pubkey = private_key.public_key(&secp);
    Address::p2pkh(&self_pubkey, private_key.network)
}

pub mod test_vectors {
    use crate::blockdata::Block;
    use crate::net::SignerID;
    use crate::signer_node::SharedSecret;
    use bitcoin::{PrivateKey, PublicKey};
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, FE, GE};
    use serde_json::Value;
    use std::fs::read_to_string;
    use std::str::FromStr;

    pub fn load_test_vector(file: &str) -> Result<Value, LoadJsonFileError> {
        let content = read_to_string(file).or(Err(LoadJsonFileError {
            path: file.to_string(),
        }))?;
        serde_json::from_str(&content).or(Err(LoadJsonFileError {
            path: file.to_string(),
        }))
    }
    #[derive(Debug)]
    pub struct LoadJsonFileError {
        pub path: String,
    }

    pub fn to_signer_id(hex: &String) -> SignerID {
        SignerID {
            pubkey: PublicKey::from_str(&hex[..]).unwrap(),
        }
    }

    pub fn to_public_key(hex: &Value) -> PublicKey {
        PublicKey::from_str(hex.as_str().unwrap()).unwrap()
    }

    pub fn private_key_from_wif(wif: &Value) -> PrivateKey {
        PrivateKey::from_wif(wif.as_str().unwrap()).unwrap()
    }

    pub fn to_fe(fe: &Value) -> FE {
        ECScalar::from(&BigInt::from_str_radix(fe.as_str().unwrap(), 16).unwrap())
    }

    pub fn to_point(ge: &Value) -> GE {
        ECPoint::from_coor(
            &BigInt::from_str_radix(ge["x"].as_str().unwrap(), 16).unwrap(),
            &BigInt::from_str_radix(ge["y"].as_str().unwrap(), 16).unwrap(),
        )
    }

    pub fn to_block(block: &Value) -> Block {
        let hex = hex::decode(block.as_str().unwrap()).unwrap();
        Block::new(hex)
    }

    pub fn to_shared_secret(value: &Value, sharing_params: ShamirSecretSharing) -> SharedSecret {
        let commitments = value["vss"]["commitments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|commitments| to_point(commitments))
            .collect();
        SharedSecret {
            vss: VerifiableSS {
                parameters: sharing_params,
                commitments: commitments,
            },
            secret_share: to_fe(&value["secret_share"]),
        }
    }
}
