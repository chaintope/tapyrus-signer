// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::crypto::multi_party_schnorr::*;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};

use crate::errors::Error;
use crate::signer_node::SharedSecretMap;
use crate::signer_node::ToShares;
use crate::signer_node::ToVerifiableSS;
use crate::util::*;
use secp256k1::rand::thread_rng;
use tapyrus::hash_types::BlockSigHash;

pub struct Sign;

impl Sign {
    pub fn private_key_to_big_int(key: tapyrus::secp256k1::SecretKey) -> Option<BigInt> {
        let value = format!("{}", key);
        let n = BigInt::from_hex(&value);
        Some(n)
    }

    pub fn create_key(index: usize, pk: Option<BigInt>) -> Keys {
        let u: FE = match pk {
            Some(i) => ECScalar::from(&i),
            None => {
                let seckey = tapyrus::secp256k1::SecretKey::new(&mut thread_rng());
                let bn = BigInt::from(&seckey[..]);
                ECScalar::from(&bn)
            }
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
        secret_shares: &SharedSecretMap,
        index: &usize,
    ) -> Result<SharedKeys, Error> {
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
            false => Err(Error::InvalidSS),
        }
    }

    pub fn sign(
        eph_shared_keys: &SharedKeys,
        priv_shared_keys: &SharedKeys,
        message: BlockSigHash,
    ) -> LocalSig {
        let local_sig =
            LocalSig::compute(&message[..], &eph_shared_keys, &priv_shared_keys);
        local_sig
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
        let v_as_int = signature.v.x_coor().unwrap();
        let v_as_str = v_as_int.to_str_radix(16);
        let s_as_int = signature.sigma.to_big_int();
        let s_as_str = s_as_int.to_str_radix(16);
        format!("{:0>64}{:0>64}", v_as_str, s_as_str)
    }
}

#[test]
fn test_private_key_to_big_int() {
    use std::str::FromStr;

    let key = tapyrus::secp256k1::SecretKey::from_str(
        "657440783dd10977c49f87c51dc68b63508e88c7ea9371dc19e6fcd0f5f8639e",
    )
    .unwrap();
    assert_eq!(
        Sign::private_key_to_big_int(key).unwrap(),
        BigInt::from_str(
            "45888996919894035081237286108090342830506757770293597094224988299678468039582"
        )
        .unwrap()
    );
}

#[test]
fn test_create_key() {
    use curv::elliptic::curves::secp256_k1::*;
    use std::str::FromStr;

    let pk = BigInt::from_str(
        "45888996919894035081237286108090342830506757770293597094224988299678468039582",
    )
    .unwrap();
    let key = Sign::create_key(0, Some(pk.clone()));
    assert_eq!(key.party_index, 0);
    assert_eq!(key.u_i, ECScalar::from(&pk));
    let x = BigInt::from_str(
        "59785365775367791548524849652375710528443431367690667459926784930515989662882",
    )
    .unwrap();
    let y = BigInt::from_str(
        "90722439330137878450843117102075228343061266416912046868469127729012019088799",
    )
    .unwrap();
    assert_eq!(key.y_i, Secp256k1Point::from_coor(&x, &y));

    // When generate random secret key, it should not raise any panic.
    Sign::create_key(1, None);
}

#[test]
fn test_format_signature() {
    use curv::elliptic::curves::secp256_k1::*;
    use std::str::FromStr;

    let pk = BigInt::from_str(
        "109776030561885333132557262259067839518424530456572565024242550494358478943987",
    )
    .unwrap();
    let x = BigInt::from_str(
        "90077539296702276303134969795375843753866389548876542277234805612812650094225",
    )
    .unwrap();
    let y = BigInt::from_str(
        "87890325134225311191847774682692230651684221898402757774563799733641956930425",
    )
    .unwrap();

    let sig = Signature {
        sigma: ECScalar::from(&pk),
        v: Secp256k1Point::from_coor(&x, &y),
    };
    assert_eq!(Sign::format_signature(&sig), "c726149bfb2d4ab64823e0cfd8245645a7950e605ef9222735d821ae570b1e91f2b3080d94faf40969c08b663ff1556fe7fbbcfcb648ac2763c16a15a08676f3");

    let sig_0 = Signature {
        sigma: ECScalar::from(&BigInt::one()),
        v: Secp256k1Point::from_coor(&x, &y),
    };
    assert_eq!(Sign::format_signature(&sig_0), "c726149bfb2d4ab64823e0cfd8245645a7950e605ef9222735d821ae570b1e910000000000000000000000000000000000000000000000000000000000000001");
}
