use bitcoin::{PrivateKey, Address};
use secp256k1::{Secp256k1, Message, Signature};
use crate::rpc::Rpc;
use bitcoin_hashes::{sha256d, Hash};
use serde_json::from_slice;
use secp256k1;

#[derive(Debug)]
enum Error {
    InvalidLength(usize, usize),
}

struct BlockHash([u8; 32]);

impl BlockHash {
    const LEN: usize = 32;

    fn from_slice(sl: &[u8]) -> Result<BlockHash, Error> {
        if sl.len() != Self::LEN {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(BlockHash(ret))
        }
    }

    fn into_inner(self) -> [u8; 32] {
        self.0
    }

    fn borrow_inner(&self) -> &[u8; 32] {
        &self.0
    }
}

fn get_next_candidate_block(rpc: &Rpc, address: Address) ->  Vec<u8> {
    // get next candidate block
    let block_hex = rpc.getnewblock(&address).unwrap();
    hex::decode(block_hex.as_str().unwrap()).expect("Decoding block hex failed")
}

fn get_block_hash(block: &Vec<u8>) -> Result<BlockHash, Error> {
    let header = &block[..104]; // Length of block header without proof is 104 bytes.
    let mut hash = sha256d::Hash::hash(header).into_inner();
    Ok(BlockHash::from_slice(&hash).unwrap())
}

fn sign(private_key: &PrivateKey, hash: &BlockHash) -> Signature {
    let sign = Secp256k1::signing_only();
    let message = Message::from_slice(&(hash.borrow_inner())[..]).unwrap();
    sign.sign(&message, &(private_key.key))
}

pub fn process_master_round() {
    // initialize
    let rpc = Rpc::new("http://127.0.0.1:12381".to_string(), Some("user".to_string()), Some("pass".to_string()));
    let private_key = PrivateKey::from_wif("cVkWtN9SaP8ywfyG1AwwjsZ5orN6a2x5wTaW2gGWkUCJVEPorDeK").unwrap();

    // call getnewblock rpc
    let secp = Secp256k1::new();
    let address = Address::p2pkh(&private_key.public_key(&secp), private_key.network);
    let block = get_next_candidate_block(&rpc, address);

    // call testproposedblock RPC
    // In real master round, this phase is not necessary. Because in getnewblock RPC already tested.
    rpc.testproposedblock(&block)?;

    // create sign with secp256k1
    let block_hash = get_block_hash(&block).unwrap();
    let sig = sign(&private_key, &block_hash);
}


#[cfg(test)]
mod test {
    use bitcoin_hashes::sha256d;
    use bitcoin::PrivateKey;
    use base64;
    use crate::test_helper::{TestKeys, get_block};
    use super::*;

    #[test]
    fn sign_test() {
        let private_key = TestKeys::new().key[0];
        let block = get_block();
        let block_hash = get_block_hash(&block).unwrap();

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
}
