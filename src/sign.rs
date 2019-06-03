use bitcoin::PrivateKey;
use secp256k1::{Signature, Secp256k1, Message};
use crate::blockdata::BlockHash;

pub fn sign(private_key: &PrivateKey, hash: &BlockHash) -> Signature {
    let sign = Secp256k1::signing_only();
    let message = Message::from_slice(&(hash.borrow_inner())[..]).unwrap();
    sign.sign(&message, &(private_key.key))
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
