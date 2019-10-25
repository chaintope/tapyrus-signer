// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::blockdata::BlockHash;
use bitcoin::PrivateKey;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::*;
use multi_party_schnorr::Error::InvalidSS;
use secp256k1::{Message, Secp256k1, Signature};

use crate::errors::Error;
use crate::signer_node::SharedSecretMap;
use crate::signer_node::ToShares;
use crate::signer_node::ToVerifiableSS;
use crate::util::*;

pub struct Sign;

impl Sign {
    /// return SharedKeys { y, x_i },
    /// where y is a aggregated public key and x_i is a share of player i.
    pub fn verify_vss_and_construct_key(
        params: &Parameters,
        secret_shares: &SharedSecretMap,
        index: &usize,
    ) -> Result<SharedKeys, multi_party_schnorr::Error> {
        assert_eq!(secret_shares.len(), params.share_count);

        let correct_ss = secret_shares
            .values()
            .map(|v| v.vss.validate_share(&v.share, *index))
            .all(|result| result.is_ok());
        let y_vec: Vec<GE> = secret_shares
            .to_vss()
            .iter()
            .map(|vss| vss.commitments[0])
            .collect();
        match correct_ss {
            true => {
                let y = sum_point(&y_vec);
                let x_i = secret_shares
                    .to_shares()
                    .iter()
                    .fold(FE::zero(), |acc, x| acc + x);
                Ok(SharedKeys { y, x_i })
            }
            false => Err(InvalidSS),
        }
    }
}

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
