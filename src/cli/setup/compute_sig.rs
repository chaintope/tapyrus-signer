use crate::blockdata::Block;
use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::cli::setup::vss_to_bidirectional_shared_secret_map;
use crate::cli::setup::vss_to_shared_secret_map;
use crate::crypto::multi_party_schnorr::LocalSig;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::sign::Sign;

use bitcoin::{PrivateKey, PublicKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

pub struct ComputeSigResponse {
    block_with_signature: Block,
}

impl ComputeSigResponse {
    fn new(block_with_signature: Block) -> Self {
        ComputeSigResponse {
            block_with_signature: block_with_signature,
        }
    }
}

impl Response for ComputeSigResponse {}

impl fmt::Display for ComputeSigResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.block_with_signature.hex())
    }
}

pub struct ComputeSigCommand {}

impl<'a> ComputeSigCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let private_key: PrivateKey = matches
            .value_of("private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("private_key".to_string()))?;

        let threshold: usize = matches
            .value_of("threshold")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error::InvalidArgs("threshold".to_string()))?;

        let aggregated_public_key: PublicKey = matches
            .value_of("aggregated_public_key")
            .and_then(|hex| PublicKey::from_str(hex).ok())
            .ok_or(Error::InvalidArgs("aggregated_public_key".to_string()))?;

        let node_secret_share: FE = matches
            .value_of("node_secret_share")
            .and_then(|s| {
                Some(ECScalar::from(
                    &BigInt::from_str(s).expect("node_secret_share is invalid"),
                ))
            })
            .ok_or(Error::InvalidArgs("node_secret_share".to_string()))?;

        let block: Block = matches
            .value_of("block")
            .and_then(|s| Some(Block::new(hex::decode(s).expect("failed to decode block"))))
            .ok_or(Error::InvalidArgs("block".to_string()))?;

        let node_vss_vec: Vec<Vss> = matches
            .values_of("node_vss")
            .ok_or(Error::InvalidArgs("node_vss is invalid".to_string()))?
            .map(|s| Vss::from_str(s))
            .collect::<Result<Vec<Vss>, _>>()?;

        let block_vss_vec: Vec<Vss> = matches
            .values_of("block_vss")
            .ok_or(Error::InvalidArgs("block_vss is invalid".to_string()))?
            .map(|s| Vss::from_str(s))
            .collect::<Result<Vec<Vss>, _>>()?;

        let keyed_local_sigs: Vec<(LocalSig, PublicKey)> = matches
            .values_of("sig")
            .ok_or(Error::InvalidArgs("local_sig is invalid".to_string()))?
            .map(|s| {
                let gamma_i = ECScalar::from(
                    &BigInt::from_str_radix(&s[0..64], 16).expect("value gamma is invalid"),
                );
                let e = ECScalar::from(
                    &BigInt::from_str_radix(&s[64..128], 16).expect("value e is invalid"),
                );
                let public_key = PublicKey::from_str(&s[128..]).expect("public_key is invalid");
                (
                    LocalSig {
                        gamma_i: gamma_i,
                        e: e,
                    },
                    public_key,
                )
            })
            .collect::<Vec<(LocalSig, PublicKey)>>();

        assert_eq!(
            block_vss_vec.len(),
            node_vss_vec.len(),
            "the length of block vss should equal to the length of node vss"
        );
        assert_eq!(
            keyed_local_sigs.len(),
            node_vss_vec.len(),
            "the length of sig should equal to the length of node vss"
        );

        let mut public_keys: Vec<PublicKey> = block_vss_vec
            .iter()
            .map(|vss| vss.sender_public_key)
            .collect();
        public_keys.sort();

        let index = index_of(&private_key, &public_keys);

        let params = ShamirSecretSharing {
            threshold: threshold - 1,
            share_count: public_keys.len(),
        };
        let shared_block_secrets = vss_to_bidirectional_shared_secret_map(&block_vss_vec, &params);

        let bytes: Vec<u8> = aggregated_public_key.key.serialize_uncompressed().to_vec();
        let point = GE::from_bytes(&bytes[1..]).expect("failed to convert to point");
        let priv_shared_keys = SharedKeys {
            y: point,
            x_i: node_secret_share,
        };

        let (is_positive, block_shared_keys, _local_sig) = Vss::create_local_sig_from_shares(
            &priv_shared_keys,
            index,
            &shared_block_secrets,
            &block,
        )?;

        let shared_secrets = vss_to_shared_secret_map(&node_vss_vec, &params);

        let mut signatures = BTreeMap::new();
        for (sig, public_key) in keyed_local_sigs {
            signatures.insert(SignerID { pubkey: public_key }, (sig.gamma_i, sig.e));
        }
        let signature = Vss::aggregate_and_verify_signature(
            &block,
            signatures,
            &public_keys,
            &shared_secrets,
            &Some((is_positive, block_shared_keys.x_i, block_shared_keys.y)),
            &shared_block_secrets,
            &priv_shared_keys,
        )?;
        let hash = block.sighash().into_inner();
        signature.verify(&hash, &priv_shared_keys.y)?;
        let sig_hex = Sign::format_signature(&signature);
        let new_block: Block = block.add_proof(hex::decode(sig_hex).unwrap());
        Ok(Box::new(ComputeSigResponse::new(new_block)))
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("computesig").args(&[
            Arg::with_name("private_key")
                .long("private_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("threshold")
                .long("threshold")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("block")
                .long("block")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("node_secret_share")
                .long("node_secret_share")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("aggregated_public_key")
                .long("aggregated_public_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("node_vss")
                .long("node_vss")
                .required(true)
                .multiple(true)
                .takes_value(true),
            Arg::with_name("block_vss")
                .long("block_vss")
                .required(true)
                .multiple(true)
                .takes_value(true),
            Arg::with_name("sig")
                .long("sig")
                .required(true)
                .multiple(true)
                .takes_value(true),
        ])
    }
}
