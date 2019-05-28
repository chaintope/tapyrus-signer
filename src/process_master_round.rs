use bitcoin::{PrivateKey, Address};
use secp256k1::{Secp256k1, Message, Signature};
use crate::rpc::Rpc;
use bitcoin_hashes::{sha256d, Hash};
use serde_json::from_slice;
use secp256k1;

fn get_next_candidate_block(rpc: &Rpc, address: Address) ->  Vec<u8> {
    // get next candidate block
    let block_hex = rpc.getnewblock(&address).unwrap();
    hex::decode(block_hex.as_str().unwrap()).expect("Decoding block hex failed")
}

fn sign(private_key: &PrivateKey, hash: sha256d::Hash) -> Signature {
    let sign = Secp256k1::signing_only();
    let message = Message::from_slice(&(hash.into_inner())[..]).unwrap();
    sign.sign(&message, &(private_key.key))
}

#[test]
fn sign_test() {

}

pub fn process_master_round() {
    // initialize
    let rpc = Rpc::new("http://127.0.0.1:12381".to_string(), Some("user".to_string()), Some("pass".to_string()));
    let private_key = PrivateKey::from_wif("cVkWtN9SaP8ywfyG1AwwjsZ5orN6a2x5wTaW2gGWkUCJVEPorDeK").unwrap();

    // call getnewblock rpc
    let secp = Secp256k1::new();
    let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
    let block = get_next_candidate_block(&rpc, address);
    let header = &block[..104]; // Length of block header without proof is 104 bytes.
    println!("{:?}", header);

    // get block hash
    let block_hash = sha256d::Hash::hash(header);
    println!("{:?}", block_hash.into_inner());

    // create sign with secp256k1
    let sig = sign(&private_key, block_hash);
    println!("{:?}", sig);
}

#[test]
fn sha256d_test() {
    let block_header = hex::decode("0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2\
    b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74\
    df2b9441a42a14695").unwrap();

    let expected_bytes = sha256d::Hash::from_slice(
        &[0x1d, 0xbd, 0x98, 0x1f, 0xe6, 0x98,
            0x57, 0x76, 0xb6, 0x44, 0xb1, 0x73,
            0xa4, 0xd0, 0x38, 0x5d, 0xdc, 0x1a,
            0xa2, 0xa8, 0x29, 0x68, 0x8d, 0x1e,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00]).unwrap();

    assert_eq!(sha256d::Hash::hash(&block_header), expected_bytes);
}