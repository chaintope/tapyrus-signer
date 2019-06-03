use bitcoin::{PrivateKey, Address};
use secp256k1::{Secp256k1, Message};
use secp256k1;

use crate::rpc::Rpc;
use crate::sign::sign;
use crate::errors::Error;

pub fn process_master_round() -> Result<(), Error> {
    // initialize
    let rpc = Rpc::new("http://127.0.0.1:12381".to_string(), Some("user".to_string()), Some("pass".to_string()));
    let private_key = PrivateKey::from_wif("cVkWtN9SaP8ywfyG1AwwjsZ5orN6a2x5wTaW2gGWkUCJVEPorDeK").unwrap();

    // call getnewblock rpc
    let secp = Secp256k1::new();
    let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
    let block = rpc.getnewblock(&address)?;

    // call testproposedblock RPC
    // In real master round, this phase is not necessary. Because in getnewblock RPC already tested.
    rpc.testproposedblock(&block)?;

    // create sign with secp256k1
    let block_hash = block.hash().unwrap();
    let sig = sign(&private_key, &block_hash);

    // combine block signatures
    let sigs = vec![sig];
    let block = rpc.combineblocksigs(&block, &sigs)?;

    // submitblock
    rpc.submitblock(&block)?;

    Ok(())
}