extern crate tapyrus_siner;
extern crate bitcoin;
extern crate log;
extern crate redis;

use bitcoin::{PrivateKey, PublicKey};
use tapyrus_siner::signer_node::{NodeParameters, SignerNode};
use std::str::FromStr;
use tapyrus_siner::net::{RedisManager};

fn main() {
    // todo: get pubkey_list and threshold from arguments.
    let pubkey_list = vec![
        PublicKey::from_str("03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc").unwrap(),
        PublicKey::from_str("02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900").unwrap(),
        PublicKey::from_str("02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e").unwrap(),
    ];
    let threshold = 2;
    let private_key = PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();

    let params = NodeParameters { pubkey_list, threshold, private_key };
    let con = RedisManager::new();

    let node = &mut SignerNode::new(con, params);
    node.start();
}



