// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::blockdata::BlockHash;
use bitcoin::PrivateKey;
use secp256k1::{Message, Secp256k1, Signature};

pub fn sign(private_key: &PrivateKey, hash: &BlockHash) -> Signature {
    let sign = Secp256k1::signing_only();
    let message = Message::from_slice(&(hash.borrow_inner())[..]).unwrap();
    sign.sign(&message, &(private_key.key))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helper::{get_block, TestKeys};
    use base64;

    #[test]
    fn sign_test() {
        let private_key = TestKeys::new().key[0];
        let block = get_block(0);
        let block_hash = block.hash().unwrap();

        let sig = sign(&private_key, &block_hash);

        assert_eq!("MEQCIDAL9iCj1rcP+pkj04erS31tGOtpOSKbCsNmG2796U+9AiADPTOWf1PxAhaaX+cZHW1ZAaJNNwoTBwqDM3V4Xz3j3g==",
                   base64::encode(&sig.serialize_der()));

        // check verifiable
        let secp = Secp256k1::new();
        let message = Message::from_slice(&(block_hash.borrow_inner())[..]).unwrap();
        let public_key = private_key.public_key(&secp).key;
        assert!(&secp.verify(&message, &sig, &public_key).is_ok());
    }
}
