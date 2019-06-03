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

#[cfg(test)]
mod test {
    use base64;
    use crate::test_helper::{TestKeys, get_block};
    use super::*;

    #[test]
    fn sign_test() {
        let private_key = TestKeys::new().key[0];
        let block = get_block();
        let block_hash = block.hash().unwrap();

        let sig = sign(&private_key, &block_hash);

        assert_eq!("MEUCIQDRTksobD+H7H46+EXJhsZ7CWSIZcqohndyAFYkEe6YvgIgWwzqhQr/IHrX+RU+CliF35tFzasfaXINrhWfdqErOok=",
                   base64::encode(&sig.serialize_der()));

        // check verifiable
        let secp = Secp256k1::new();
        let verify = Secp256k1::verification_only();
        let message = Message::from_slice(&(block_hash.borrow_inner())[..]).unwrap();
        let public_key = private_key.public_key(&secp).key;
        assert!(verify.verify(&message, &sig, &public_key).is_ok());

    }
}
