// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

extern crate tapyrus_signer;
use bitcoin::{Address, PrivateKey};
use secp256k1;
use secp256k1::Secp256k1;

use tapyrus_signer::rpc::{Rpc, TapyrusApi};
use tapyrus_signer::sign::sign;

pub fn main() {
    // initialize
    let rpc = Rpc::new(
        "http://127.0.0.1:12381".to_string(),
        Some("user".to_string()),
        Some("pass".to_string()),
    );
    let private_key =
        PrivateKey::from_wif("cUwpWhH9CbYwjUWzfz1UVaSjSQm9ALXWRqeFFiZKnn8cV6wqNXQA").unwrap();
    // call getnewblock rpc
    let secp = Secp256k1::new();
    let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
    println!("address: {:?}", address.to_string());
    let block = rpc.getnewblock(&address).unwrap();

    println!("block: {:?}", block);
    // call testproposedblock RPC
    // In real master round, this phase is not necessary. Because in getnewblock RPC already tested.
    rpc.testproposedblock(&block).unwrap();

    // create sign with secp256k1
    let block_hash = block.hash().unwrap();
    let sig = sign(&private_key, &block_hash);

    // combine block signatures
    let sigs = vec![sig];
    let block = rpc.combineblocksigs(&block, &sigs).unwrap();

    // submitblock
    rpc.submitblock(&block).unwrap();
}
