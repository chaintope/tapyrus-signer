/*
    Multisig Schnorr

    Copyright 2018 by Kzen Networks
    Copyright 2020 by Chaintope Inc.

    This file is copied from Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>
*/
/// following the variant used in bip-schnorr: https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
use crate::errors::Error::{self, InvalidKey, InvalidSS, InvalidSig};

use curv::arithmetic::traits::*;

use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{BigInt, FE, GE};
use sha2::{Digest, Sha256};

const SECURITY: usize = 256;

pub struct Keys {
    pub u_i: FE,
    pub y_i: GE,
    pub party_index: usize,
}

pub struct KeyGenBroadcastMessage1 {
    com: BigInt,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
}

impl PartialEq for SharedKeys {
    fn eq(&self, other: &SharedKeys) -> bool {
        self.x_i.get_element() == other.x_i.get_element()
            && self.y.get_element() == other.y.get_element()
    }
}

impl Eq for SharedKeys {}

impl Keys {
    pub fn phase1_create(index: usize) -> Keys {
        let u: FE = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index.clone(),
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, BigInt) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.y_i.bytes_compressed_to_big_int(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 { com };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &Vec<BigInt>,
        y_vec: &Vec<GE>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
        parties: &[usize],
    ) -> Result<(VerifiableSS, Vec<FE>, usize), Error> {
        // test length:
        assert_eq!(blind_vec.len(), params.share_count);
        assert_eq!(bc1_vec.len(), params.share_count);
        assert_eq!(y_vec.len(), params.share_count);
        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &y_vec[i].bytes_compressed_to_big_int(),
                    &blind_vec[i],
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);
        /*
        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            parties,
        );
        */
        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            &parties,
        );

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(InvalidKey),
        }
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        y_vec: &Vec<GE>,
        secret_shares_vec: &Vec<FE>,
        vss_scheme_vec: &Vec<VerifiableSS>,
        index: &usize,
    ) -> Result<SharedKeys, Error> {
        assert_eq!(y_vec.len(), params.share_count);
        assert_eq!(secret_shares_vec.len(), params.share_count);
        assert_eq!(vss_scheme_vec.len(), params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut y_vec_iter = y_vec.iter();
                let y0 = y_vec_iter.next().unwrap();
                let y = y_vec_iter.fold(y0.clone(), |acc, x| acc + x);
                let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
                Ok(SharedKeys { y, x_i })
            }
            false => Err(InvalidSS),
        }
    }

    // remove secret shares from x_i for parties that are not participating in signing
    pub fn update_shared_key(
        shared_key: &SharedKeys,
        parties_in: &[usize],
        secret_shares_vec: &Vec<FE>,
    ) -> SharedKeys {
        let mut new_xi: FE = FE::zero();
        for i in 0..secret_shares_vec.len() {
            if parties_in.iter().find(|&&x| x == i).is_some() {
                new_xi = new_xi + &secret_shares_vec[i]
            }
        }
        SharedKeys {
            y: shared_key.y.clone(),
            x_i: new_xi,
        }
    }
}

pub struct LocalSig {
    pub gamma_i: FE,
    pub e: FE,
}

impl LocalSig {
    pub fn compute(
        message: &[u8],
        local_ephemaral_key: &SharedKeys,
        local_private_key: &SharedKeys,
    ) -> LocalSig {
        let beta_i = local_ephemaral_key.x_i.clone();
        let alpha_i = local_private_key.x_i.clone();

        let e: FE = compute_e(&local_ephemaral_key.y, &local_private_key.y, message);
        let gamma_i = beta_i + e.clone() * alpha_i;
        //   let gamma_i = e.clone() * alpha_i ;

        LocalSig { gamma_i, e }
    }

    // section 4.2 step 3
    #[allow(unused_doc_comments)]
    pub fn verify_local_sigs(
        gamma_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        vss_private_keys: &Vec<VerifiableSS>,
        vss_ephemeral_keys: &Vec<VerifiableSS>,
    ) -> Result<VerifiableSS, Error> {
        //parties_index_vec is a vector with indices of the parties that are participating and provided gamma_i for this step
        // test that enough parties are in this round
        assert!(parties_index_vec.len() > vss_private_keys[0].parameters.threshold);

        // Vec of joint commitments:
        // n' = num of signers, n - num of parties in keygen
        // [com0_eph_0,... ,com0_eph_n', e*com0_kg_0, ..., e*com0_kg_n ;
        // ...  ;
        // comt_eph_0,... ,comt_eph_n', e*comt_kg_0, ..., e*comt_kg_n ]
        let comm_vec = (0..vss_private_keys[0].parameters.threshold + 1)
            .map(|i| {
                let mut key_gen_comm_i_vec = (0..vss_private_keys.len())
                    .map(|j| vss_private_keys[j].commitments[i].clone() * &gamma_vec[i].e)
                    .collect::<Vec<GE>>();
                let mut eph_comm_i_vec = (0..vss_ephemeral_keys.len())
                    .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
                    .collect::<Vec<GE>>();
                key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
                let mut comm_i_vec_iter = key_gen_comm_i_vec.iter();
                let comm_i_0 = comm_i_vec_iter.next().unwrap();
                comm_i_vec_iter.fold(comm_i_0.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<GE>>();

        let vss_sum = VerifiableSS {
            parameters: vss_ephemeral_keys[0].parameters.clone(),
            commitments: comm_vec,
        };

        let g: GE = GE::generator();
        let correct_ss_verify = (0..parties_index_vec.len())
            .map(|i| {
                let gamma_i_g = &g * &gamma_vec[i].gamma_i;
                vss_sum
                    .validate_share_public(&gamma_i_g, parties_index_vec[i] + 1)
                    .is_ok()
            })
            .collect::<Vec<bool>>();

        match correct_ss_verify.iter().all(|x| x.clone() == true) {
            true => Ok(vss_sum),
            false => Err(InvalidSS),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: FE,
    pub v: GE,
}

impl Signature {
    pub fn generate(
        vss_sum_local_sigs: &VerifiableSS,
        local_sig_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        v: GE,
    ) -> Signature {
        let gamma_vec = (0..parties_index_vec.len())
            .map(|i| local_sig_vec[i].gamma_i.clone())
            .collect::<Vec<FE>>();
        let reconstruct_limit = vss_sum_local_sigs.parameters.threshold.clone() + 1;
        let sigma = vss_sum_local_sigs.reconstruct(
            &parties_index_vec[0..reconstruct_limit.clone()],
            &gamma_vec[0..reconstruct_limit.clone()],
        );
        Signature { sigma, v }
    }

    pub fn verify(&self, message: &[u8], pubkey_y: &GE) -> Result<(), Error> {
        let e: FE = compute_e(&self.v, pubkey_y, message);
        let g: GE = GE::generator();
        let sigma_g = g * &self.sigma;
        let e_y = pubkey_y * &e;
        let e_y_plus_v = e_y + &self.v;

        if e_y_plus_v == sigma_g {
            Ok(())
        } else {
            Err(InvalidSig)
        }
    }
}

fn compute_e(r: &GE, y: &GE, message: &[u8]) -> FE {
    let mut hasher = Sha256::new();
    hasher.input(&r.get_element().serialize()[1..33]);
    hasher.input(&y.get_element().serialize()[..]);
    hasher.input(message);
    let e_bn = BigInt::from(&hasher.result()[..]);

    ECScalar::from(&e_bn)
}

#[cfg(test)]
mod tests {
    use super::compute_e;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, FE, GE};

    #[test]
    fn test_compute_e() {
        let g: GE = ECPoint::generator();

        let v: GE = {
            // Public key from this secret key is '02008459be0a43dee493998b3e5e186323b9c1f1590765c82f650e425fcf074063'. Its x coordinate starts with "00".
            let bn = BigInt::from_str_radix(
                "8c36e52e1d9f5c62634001393e81c65d427e8dd60f9eeac866d2c46adcc65107",
                16,
            )
                .unwrap();
            let fe: FE = ECScalar::from(&bn);
            g * fe
        };
        let y: GE = {
            // Just random secret key
            let bn = BigInt::from_str_radix(
                "1d11656e57924a03cd12d5f3517e286bf697255642565405d78eeebcc20d43c0",
                16,
            )
                .unwrap();
            let fe: FE = ECScalar::from(&bn);
            g * fe
        };

        // It should be equal to expected when the message started with "00" byte.
        let message =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();

        let expected: FE = {
            let bn = BigInt::from(
                &vec![
                    0_u8, 220, 239, 27, 2, 169, 72, 198, 246, 203, 60, 29, 33, 4, 45, 45, 116, 78,
                    14, 99, 132, 151, 24, 148, 213, 219, 76, 18, 200, 223, 98, 93,
                ][..],
            );
            ECScalar::from(&bn)
        };

        assert_eq!(expected, compute_e(&v, &y, &message[..]));
    }
}

#[cfg(test)]
mod test;