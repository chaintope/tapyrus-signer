extern crate bitcoin;
extern crate secp256k1;
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate bitcoin_hashes;
extern crate jsonrpc;
extern crate hex;
extern crate byteorder;
extern crate base64;
extern crate redis;

use bitcoin::{PrivateKey, PublicKey};
use crate::signer_node::{NodeParameters, SignerNode};
use std::str::FromStr;
use crate::signer::{RoundState, Joining};
use crate::net::{RedisManager, MessageType, ConnectionManager};
use redis::ControlFlow;

mod blockdata;
mod rpc;
mod process_master_round;
mod sign;
mod test_helper;
mod errors;
mod net;
mod signer;
mod signer_node;


fn main() {
    // todo: get pubkey_list and threshold from arguments.
    let pubkey_list = vec![
        PublicKey::from_str("03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc").unwrap(),
        PublicKey::from_str("02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900").unwrap(),
        PublicKey::from_str("02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e").unwrap(),
    ];
    let threshold = 2;
    let privateKey = PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();

    let params = NodeParameters { pubkey_list, threshold, privateKey, };
    let round_state = Box::new(Joining {});
    let con = RedisManager::new();

    let mut node = SignerNode::new(Box::new(con), round_state, params);
    node.start();
}



