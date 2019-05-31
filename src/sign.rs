use bitcoin::PrivateKey;
use secp256k1::{Signature, Secp256k1, Message};
use crate::blockdata::BlockHash;

pub fn sign(private_key: &PrivateKey, hash: &BlockHash) -> Signature {
    let sign = Secp256k1::signing_only();
    let message = Message::from_slice(&(hash.borrow_inner())[..]).unwrap();
    sign.sign(&message, &(private_key.key))
}