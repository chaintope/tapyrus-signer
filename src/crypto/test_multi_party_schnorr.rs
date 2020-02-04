#![allow(non_snake_case)]
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
use crate::crypto::multi_party_schnorr::*;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{FE, GE};

#[test]
#[allow(unused_doc_comments)]
fn test_t2_n4() {
    /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties as well.
    let t = 2;
    let n = 4;
    let key_gen_parties_index_vec: [usize; 4] = [0, 1, 2, 3];
    let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
        .map(|i| key_gen_parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();

    let (_priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
    let parties_index_vec: [usize; 4] = [0, 1, 2, 3];
    let parties_points_vec = (0..parties_index_vec.len())
        .map(|i| parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();

    let (_eph_keys_vec, eph_shared_keys_vec, V, eph_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &parties_points_vec);
    let message: [u8; 4] = [79, 77, 69, 82];
    let local_sig_vec = (0..n.clone())
        .map(|i| LocalSig::compute(&message, &eph_shared_keys_vec[i], &priv_shared_keys_vec[i]))
        .collect::<Vec<LocalSig>>();
    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &key_gen_vss_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());
    let vss_sum_local_sigs = verify_local_sig.unwrap();
    let signature = Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, V);
    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());
}

#[test]
#[allow(unused_doc_comments)]
fn test_t2_n5_sign_with_4() {
    /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties, indices 0,1,3,4.
    let t = 2;
    let n = 5;
    /// keygen:
    let key_gen_parties_index_vec: [usize; 5] = [0, 1, 2, 3, 4];
    let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
        .map(|i| key_gen_parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();
    let (_priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
    /// signing:
    let parties_index_vec: [usize; 4] = [0, 1, 3, 4];
    let parties_points_vec = (0..parties_index_vec.len())
        .map(|i| parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();
    let num_parties = parties_index_vec.len();
    let (_eph_keys_vec, eph_shared_keys_vec, V, eph_vss_vec) =
        keygen_t_n_parties(t.clone(), num_parties.clone(), &parties_points_vec);
    let message: [u8; 4] = [79, 77, 69, 82];

    // each party computes and share a local sig, we collected them here to a vector as each party should do AFTER receiving all local sigs
    let local_sig_vec = (0..num_parties.clone())
        .map(|i| {
            LocalSig::compute(
                &message,
                &eph_shared_keys_vec[i],
                &priv_shared_keys_vec[parties_index_vec[i]],
            )
        })
        .collect::<Vec<LocalSig>>();

    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &key_gen_vss_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());
    let vss_sum_local_sigs = verify_local_sig.unwrap();

    /// each party / dealer can generate the signature
    let signature = Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, V);
    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());
}

pub fn keygen_t_n_parties(
    t: usize,
    n: usize,
    parties: &[usize],
) -> (Vec<Keys>, Vec<SharedKeys>, GE, Vec<VerifiableSS>) {
    let parames = Parameters {
        threshold: t,
        share_count: n.clone(),
    };
    assert_eq!(parties.len(), n.clone());
    let party_keys_vec = (0..n.clone())
        .map(|i| Keys::phase1_create(parties[i]))
        .collect::<Vec<Keys>>();

    let mut bc1_vec = Vec::new();
    let mut blind_vec = Vec::new();
    for i in 0..n.clone() {
        let (bc1, blind) = party_keys_vec[i].phase1_broadcast();
        bc1_vec.push(bc1);
        blind_vec.push(blind);
    }

    let y_vec = (0..n.clone())
        .map(|i| party_keys_vec[i].y_i.clone())
        .collect::<Vec<GE>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();
    for i in 0..n.clone() {
        let (vss_scheme, secret_shares, index) = party_keys_vec[i]
            .phase1_verify_com_phase2_distribute(&parames, &blind_vec, &y_vec, &bc1_vec, parties)
            .expect("invalid key");
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares);
        index_vec.push(index);
    }

    let party_shares = (0..n.clone())
        .map(|i| {
            (0..n.clone())
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i].clone()
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut shared_keys_vec = Vec::new();
    for i in 0..n.clone() {
        let shared_keys = party_keys_vec[i]
            .phase2_verify_vss_construct_keypair(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                &index_vec[i],
            )
            .expect("invalid vss");
        shared_keys_vec.push(shared_keys);
    }

    (party_keys_vec, shared_keys_vec, y_sum, vss_scheme_vec)
}

use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use std::borrow::Borrow;

const STR_SECRET1: &str = "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747";
const STR_SECRET2: &str = "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117";
const STR_SECRET1C: &str = "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747";
const STR_SECRET2C: &str = "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117";

fn get_shared_keys(wif: &str) -> SharedKeys {
    let privkey: FE = ECScalar::from(&BigInt::from_hex(STR_SECRET1));

    SharedKeys {
        y: &ECPoint::generator() * &privkey,
        x_i: privkey,
    }
}

fn get_random_shared_keys() -> SharedKeys {
    let privkey = Secp256k1Scalar::new_random();

    SharedKeys {
        y: &ECPoint::generator() * &privkey,
        x_i: privkey,
    }
}

/// returns sha256 value from input.
fn hash(data: &[u8]) -> [u8; 32] {
    use bitcoin_hashes::Hash;
    let hash = bitcoin_hashes::sha256::Hash::hash(data);
    hash.into_inner()
}

#[test]
fn test_sign() {
    for n in 0..16 {
        let msg = {
            let m = format!("Very secret message {}: 11", n);
            hash(m.as_bytes())
        };

        let v = get_random_shared_keys();

        let sign1 = {
            let s = LocalSig::compute(&msg[..], &v, &get_shared_keys(STR_SECRET1));
            Signature {
                sigma: s.gamma_i,
                v: v.y,
            }
        };
        assert!(sign1
            .verify(&msg[..], &get_shared_keys(STR_SECRET1).y)
            .is_ok());

        let sign2 = {
            let s = LocalSig::compute(&msg[..], &v, &get_shared_keys(STR_SECRET2));
            Signature {
                sigma: s.gamma_i,
                v: v.y,
            }
        };
        assert!(sign2
            .verify(&msg[..], &get_shared_keys(STR_SECRET2).y)
            .is_ok());

        let sign1c = {
            let s = LocalSig::compute(&msg[..], &v, &get_shared_keys(STR_SECRET1C));
            Signature {
                sigma: s.gamma_i,
                v: v.y,
            }
        };
        assert!(sign1c
            .verify(&msg[..], &get_shared_keys(STR_SECRET1C).y)
            .is_ok());

        let sign2c = {
            let s = LocalSig::compute(&msg[..], &v, &get_shared_keys(STR_SECRET2C));
            Signature {
                sigma: s.gamma_i,
                v: v.y,
            }
        };
        assert!(sign2c
            .verify(&msg[..], &get_shared_keys(STR_SECRET2C).y)
            .is_ok());
    }
}
