use crate::net::{Message, MessageType, SignerID};
use crate::tests::helper::blocks::get_block;
use crate::tests::helper::keys::TEST_KEYS;
use tapyrus::{Address, PrivateKey};

pub mod blocks;
pub mod keys;
pub mod net;
pub mod node_parameters_builder;
pub mod node_state_builder;
pub mod node_vss;
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
    let signer_id = SignerID::new(TEST_KEYS.pubkeys()[4]);
    let block = get_block(0);
    Message {
        message_type: MessageType::Candidateblock(block),
        sender_id: signer_id,
        receiver_id: None,
    }
}

pub fn address(private_key: &PrivateKey) -> Address {
    let secp = tapyrus::secp256k1::Secp256k1::new();
    let self_pubkey = private_key.public_key(&secp);
    Address::p2pkh(&self_pubkey, private_key.network)
}

pub mod test_vectors {
    use crate::crypto::multi_party_schnorr::LocalSig;
    use crate::crypto::vss::Vss;
    use crate::federation::{Federation, Federations};
    use crate::net::SignerID;
    use crate::signer_node::NodeParameters;
    use crate::signer_node::SharedSecret;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::rpc::MockRpc;

    use tapyrus::{PrivateKey, PublicKey};
    use tapyrus::blockdata::block::Block;
    use tapyrus::consensus::encode::deserialize;

    use curv::{FE, GE};
    use serde_json::Value;
    use std::collections::HashSet;
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
        serde_json::from_value(fe.clone()).unwrap()
    }

    pub fn to_point(ge: &Value) -> GE {
        serde_json::from_value(ge.clone()).unwrap()
    }

    /// # json example
    /// "localsig": {
    ///   "gamma_i": "b42d01fd501709fe749419e404df867b72ea2dbc13ff9404f83ded4a02bb4f94",
    ///   "e": "c4604e68cdd2ef0ccef3eaf5f453ee0efa73beb9759ffa2295afa704939ec644"
    /// }
    pub fn to_local_sig(v: &Value) -> Option<LocalSig> {
        if v.is_null() {
            None
        } else {
            Some(LocalSig {
                gamma_i: to_fe(&v["gamma_i"]),
                e: to_fe(&v["e"]),
            })
        }
    }

    /// # json example
    /// "block_shared_keys": {
    ///   "positive": false,
    ///   "x_i": "0d8501d7bb411a3d854177822c91f3ffc704dae169373032f5be847676e75508",
    ///   "y": {
    ///     "x": "2ba82fcda00d9216bef8c3c5e5d47d1f8ec758d777f8a802780aaf48271940de",
    ///     "y": "eb2ee580a7a6c3abda257d16adac311a7d6fda959026423225493d663fd14cb3"
    ///   }
    /// }
    pub fn to_block_shared_keys(v: &Value) -> Option<(bool, FE, GE)> {
        if v.is_null() {
            None
        } else {
            let is_positive = v["positive"].as_bool().unwrap();
            let x_i = to_fe(&v["x_i"]);
            let y = to_point(&v["y"]);
            Some((is_positive, x_i, y))
        }
    }

    pub fn to_block(block: &Value) -> Option<Block> {
        if block.is_null() {
            None
        } else {
            let bytes = hex::decode(block.as_str().unwrap()).unwrap();
            deserialize(&bytes).ok()
        }
    }

    pub fn to_shared_secret(value: &Value) -> SharedSecret {
        serde_json::from_value(value.clone()).unwrap()
    }

    pub fn to_participants(value: &Value) -> HashSet<SignerID> {
        let r: HashSet<String> = serde_json::from_value(value.clone()).unwrap_or(HashSet::new());
        r.iter().map(|i| to_signer_id(i)).collect()
    }

    pub fn to_node_parameters(value: &Value, rpc: MockRpc) -> NodeParameters<MockRpc> {
        let node_vss: Vec<Vss> = value["node_vss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| Vss::from_str(i.as_str().unwrap()).unwrap())
            .collect();
        let threshold = value["threshold"].as_u64().unwrap();
        let aggregated_public_key = to_public_key(&value["aggregated_public_key"]);
        let public_key = to_public_key(&value["public_key"]);
        let federations = vec![Federation::new(
            public_key,
            0,
            Some(threshold as u8),
            Some(node_vss.clone()),
            aggregated_public_key,
        )];
        let federations = Federations::new(federations);
        NodeParametersBuilder::new()
            .rpc(rpc)
            .public_key(public_key)
            .federations(federations)
            .build()
    }
}
