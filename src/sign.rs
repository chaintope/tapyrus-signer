// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::collections::BTreeMap;

use crate::blockdata::BlockHash;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::*;
use multi_party_schnorr::Error::InvalidSS;

use crate::errors::Error;
use crate::signer_node::SharedSecretMap;
use crate::signer_node::ToShares;
use crate::signer_node::ToVerifiableSS;
use crate::util::*;

pub struct Sign;

impl Sign {
    pub fn private_key_to_big_int(key: secp256k1::SecretKey) -> Option<BigInt> {
        let value = format!("{}", key);
        let n = BigInt::from_hex(&value);
        Some(n)
    }

    pub fn create_key(index: usize, pk: Option<BigInt>) -> Keys {
        let u: FE = match pk {
            Some(i) => ECScalar::from(&i),
            None => ECScalar::new_random(),
        };
        let y = &ECPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index.clone(),
        }
    }

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
            .map(|v| v.vss.validate_share(&v.secret_share, *index))
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

    pub fn sign(
        eph_shared_keys: &SharedKeys,
        priv_shared_keys: &SharedKeys,
        message: BlockHash,
    ) -> Result<LocalSig, Error> {
        let message_slice = message.borrow_inner();
        let local_sig =
            LocalSig::compute(&message_slice.clone(), &eph_shared_keys, &priv_shared_keys);
        Ok(local_sig)
    }

    pub fn aggregate(
        vss_sum: &VerifiableSS,
        local_sigs: &Vec<LocalSig>,
        parties: &[usize],
        v: GE,
    ) -> Signature {
        Signature::generate(vss_sum, local_sigs, parties, v)
    }

    pub fn format_signature(signature: &Signature) -> String {
        let mut array: Vec<u8> = Vec::new();
        let v_as_int = signature.v.x_coor().unwrap();
        array.extend(curv::arithmetic::traits::Converter::to_vec(&v_as_int));
        let s_as_int = signature.sigma.to_big_int();
        array.extend(curv::arithmetic::traits::Converter::to_vec(&s_as_int));
        let as_str = array
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        format!("{:x}{}", array.len(), as_str)
    }
}
