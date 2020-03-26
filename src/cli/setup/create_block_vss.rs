use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::crypto::vss::{Commitment, Vss};
use crate::errors::Error;
use crate::sign::Sign;
use bitcoin::{PrivateKey, PublicKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

pub struct CreateBlockVssResponse {
    vss: BTreeMap<PublicKey, Vss>,
}

impl CreateBlockVssResponse {
    fn new(vss: BTreeMap<PublicKey, Vss>) -> Self {
        CreateBlockVssResponse { vss: vss }
    }
}

impl Response for CreateBlockVssResponse {}

impl fmt::Display for CreateBlockVssResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self
            .vss
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<String>>()
            .join("\n");
        write!(f, "{}", c)
    }
}

pub struct CreateBlockVssCommand {}

impl<'a> CreateBlockVssCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let node_private_key: PrivateKey = matches
            .value_of("node_private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("node_private_key".to_string()))?;

        let mut node_public_keys: Vec<PublicKey> = matches
            .values_of("node_public_key")
            .ok_or(Error::InvalidArgs("node_public_key".to_string()))?
            .map(|key| PublicKey::from_str(key).map_err(|_| Error::InvalidKey))
            .collect::<Result<Vec<PublicKey>, _>>()?;
        node_public_keys.sort();

        let block_private_key: PrivateKey = matches
            .value_of("block_private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("block_private_key".to_string()))?;

        let threshold: u64 = matches
            .value_of("threshold")
            .and_then(|t| t.parse::<u64>().ok())
            .ok_or(Error::InvalidArgs(
                "threshold should be integer.".to_string(),
            ))?;

        let index = index_of(&node_private_key, &node_public_keys);
        let pk = Sign::private_key_to_big_int(block_private_key.key);
        let key = Sign::create_key(index, pk);

        let (
            vss_scheme_for_positive,
            secret_shares_for_positive,
            vss_scheme_for_negative,
            secret_shares_for_negative,
        ) = Vss::create_block_shares(&key, threshold as usize, node_public_keys.len());
        let mut vss_map = BTreeMap::new();
        let secp = secp256k1::Secp256k1::new();
        let sender_public_key = PublicKey::from_private_key(&secp, &node_private_key);

        for j in 0..node_public_keys.len() {
            let vss = Vss {
                sender_public_key: sender_public_key,
                receiver_public_key: node_public_keys[j].clone(),
                positive_commitments: vss_scheme_for_positive
                    .commitments
                    .iter()
                    .map(|c| Commitment::from(c))
                    .collect(),
                positive_secret: secret_shares_for_positive[j],
                negative_commitments: vss_scheme_for_negative
                    .commitments
                    .iter()
                    .map(|c| Commitment::from(c))
                    .collect(),
                negative_secret: secret_shares_for_negative[j],
            };
            vss_map.insert(node_public_keys[j].clone(), vss);
        }
        Ok(Box::new(CreateBlockVssResponse::new(vss_map)))
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("createblockvss").args(&[
            Arg::with_name("block_private_key")
                .long("block_private_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("node_public_key")
                .long("node_public_key")
                .required(true)
                .multiple(true)
                .takes_value(true),
            Arg::with_name("node_private_key")
                .long("node_private_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("threshold")
                .long("threshold")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
        ])
    }
}
