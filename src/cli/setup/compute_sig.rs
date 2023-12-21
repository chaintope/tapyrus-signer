use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::cli::setup::vss_to_bidirectional_shared_secret_map;
use crate::cli::setup::vss_to_shared_secret_map;
use crate::crypto::multi_party_schnorr::LocalSig;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::rpc::Rpc;
use crate::sign::Sign;
use crate::signer_node::NodeParameters;

use clap::{App, Arg, ArgMatches, SubCommand};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use tapyrus::blockdata::block::{Block, XField};
use tapyrus::consensus::encode::{deserialize, serialize};
use tapyrus::{PrivateKey, PublicKey};

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
        write!(f, "{}", hex::encode(serialize(&self.block_with_signature)))
    }
}

pub struct ComputeXFieldSigResponse {
    xfield_signature: tapyrus::util::signature::Signature,
}

impl ComputeXFieldSigResponse {
    fn new(xfield_signature: tapyrus::util::signature::Signature) -> Self {
        ComputeXFieldSigResponse {
            xfield_signature: xfield_signature,
        }
    }
}

impl Response for ComputeXFieldSigResponse {}

impl fmt::Display for ComputeXFieldSigResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(serialize(&self.xfield_signature)))
    }
}

pub struct ComputeSigCommand {}

impl<'a> ComputeSigCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let private_key: PrivateKey = matches
            .value_of("private-key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("private-key".to_string()))?;

        let threshold: usize = matches
            .value_of("threshold")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error::InvalidArgs("threshold".to_string()))?;

        let aggregated_public_key: PublicKey = matches
            .value_of("aggregated-public-key")
            .and_then(|hex| PublicKey::from_str(hex).ok())
            .ok_or(Error::InvalidArgs("aggregated-public-key".to_string()))?;

        let node_secret_share: FE = matches
            .value_of("node-secret-share")
            .and_then(|s| BigInt::from_str_radix(s, 16).ok())
            .map(|i| ECScalar::from(&i))
            .ok_or(Error::InvalidArgs("node-secret-share".to_string()))?;

        let node_vss_vec: Vec<Vss> = matches
            .values_of("node-vss")
            .ok_or(Error::InvalidArgs("node-vss".to_string()))?
            .map(|s| Vss::from_str(s).map_err(|_| Error::InvalidArgs("node-vss".to_string())))
            .collect::<Result<Vec<Vss>, _>>()?;

        let block_vss_vec: Vec<Vss> = matches
            .values_of("block-vss")
            .ok_or(Error::InvalidArgs("block-vss".to_string()))?
            .map(|s| Vss::from_str(s).map_err(|_| Error::InvalidArgs("block-vss".to_string())))
            .collect::<Result<Vec<Vss>, _>>()?;

        let keyed_local_sigs: Vec<(LocalSig, PublicKey)> = matches
            .values_of("sig")
            .ok_or(Error::InvalidArgs("local-sig is invalid".to_string()))?
            .map(|s| {
                if s.len() != 194 {
                    return Err(Error::InvalidArgs("sig".to_string()));
                }
                let gamma_i = ECScalar::from(
                    &BigInt::from_str_radix(&s[0..64], 16)
                        .map_err(|_| Error::InvalidArgs("value gamma is invalid".to_string()))?,
                );
                let e = ECScalar::from(
                    &BigInt::from_str_radix(&s[64..128], 16)
                        .map_err(|_| Error::InvalidArgs("value e is invalid".to_string()))?,
                );
                let public_key = PublicKey::from_str(&s[128..])
                    .map_err(|_| Error::InvalidArgs("public key is invalid".to_string()))?;
                Ok((
                    LocalSig {
                        gamma_i: gamma_i,
                        e: e,
                    },
                    public_key,
                ))
            })
            .collect::<Result<Vec<(LocalSig, PublicKey)>, Error>>()?;

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

        let signing_block = matches.is_present("block");
        let block: Option<Block> = if signing_block {
            matches
                .value_of("block")
                .and_then(|s| hex::decode(s).ok())
                .and_then(|hex| deserialize::<Block>(&hex).ok())
                .ok_or(Error::InvalidArgs("block".to_string()))?
                .into()
        } else {
            None
        };

        let mut xfield = XField::None;
        if block.is_none() {
            xfield = matches
                .value_of("xfield")
                .and_then(|s| hex::decode(s).ok())
                .and_then(|hex| deserialize::<XField>(&hex).ok())
                .ok_or(Error::InvalidArgs("xfield".to_string()))?;

            match xfield {
                XField::None | XField::Unknown(_, _) => {
                    return Err(Error::InvalidArgs("xfield".to_string()));
                }
                _ => (),
            }
        }

        let mut public_keys: Vec<PublicKey> = block_vss_vec
            .iter()
            .map(|vss| vss.sender_public_key)
            .collect();
        NodeParameters::<Rpc>::sort_publickey(&mut public_keys);

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

        let (is_positive, block_shared_keys, _local_sig) = if let Some(ref block) = block {
            Vss::create_local_sig_from_shares_for_block(
                &priv_shared_keys,
                index,
                &shared_block_secrets,
                &block,
            )?
        } else if xfield != XField::None {
            Vss::create_local_sig_from_shares_for_xfield(
                &priv_shared_keys,
                index,
                &shared_block_secrets,
                &xfield,
            )?
        } else {
            return Err(Error::InvalidArgs(
                "Either xfield or block is expected".to_string(),
            ));
        };

        let shared_secrets = vss_to_shared_secret_map(&node_vss_vec, &params);

        let mut signatures = BTreeMap::new();
        for (sig, public_key) in keyed_local_sigs {
            signatures.insert(SignerID { pubkey: public_key }, (sig.gamma_i, sig.e));
        }

        let hash = if let Some(ref block) = block {
            block.header.signature_hash().to_vec()
        } else {
            xfield.signature_hash().unwrap().to_vec()
        };

        let signature = Vss::aggregate_and_verify_signature(
            &hash,
            signatures,
            &public_keys,
            &shared_secrets,
            &Some((is_positive, block_shared_keys.x_i, block_shared_keys.y)),
            &shared_block_secrets,
            &priv_shared_keys,
        )?;

        signature.verify(&hash, &priv_shared_keys.y)?;
        let sig_hex = Sign::format_signature(&signature);
        let sig: tapyrus::util::signature::Signature =
            deserialize(&hex::decode(sig_hex).map_err(|_| Error::InvalidSig)?)?;

        if let Some(mut block) = block {
            block.header.proof = Some(sig);
            Ok(Box::new(ComputeSigResponse::new(block)))
        } else {
            Ok(Box::new(ComputeXFieldSigResponse::new(sig)))
        }
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("computesig").args(&[
            Arg::with_name("private-key")
                .long("private-key")
                .required(true)
                .takes_value(true)
                .help("private key of this signer with a WIF format"),
            Arg::with_name("threshold")
                .long("threshold")
                .required(true)
                .takes_value(true)
                .help("the minimum number of signers required to sign block"),
            Arg::with_name("block")
                .long("block")
                .takes_value(true)
                .conflicts_with("xfied")
                .required_unless("xfield")
                .help("block to be signed as a hex string format"),
            Arg::with_name("xfield")
                .long("xfield")
                .takes_value(true)
                .conflicts_with("block")
                .required_unless("block")
                .help("xfield change to be signed as a hex string format"),
            Arg::with_name("node-secret-share")
                .long("node-secret-share")
                .required(true)
                .takes_value(true)
                .help("secret key share of the signers with a hex string format"),
            Arg::with_name("aggregated-public-key")
                .long("aggregated-public-key")
                .required(true)
                .takes_value(true)
                .help("aggregated public key of all signers"),
            Arg::with_name("node-vss")
                .long("node-vss")
                .required(true)
                .multiple(true)
                .takes_value(true)
                .help("the node VSSs generated by tapyrus-setup createnodevss command"),
            Arg::with_name("block-vss")
                .long("block-vss")
                .required(true)
                .multiple(true)
                .takes_value(true)
                .help("the block VSSs generated by tapyrus-setup createblockvss command"),
            Arg::with_name("sig")
                .long("sig")
                .required(true)
                .multiple(true)
                .takes_value(true)
                .help("the local signatures generated by tapyrus-setup sign command"),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_success() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert!(response.is_ok());
    }

    #[test]
    fn test_execute_invalid_threshold() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "x",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"threshold\")"
        );
    }

    #[test]
    fn test_execute_invalid_block() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "x",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"block\")"
        );
    }

    #[test]
    fn test_execute_invalid_block_vss() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "x",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"block-vss\")"
        );
    }

    #[test]
    fn test_execute_invalid_node_vss() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "x",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"node-vss\")"
        );
    }

    #[test]
    fn test_execute_invalid_node_secret_share() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "x",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"node-secret-share\")"
        );
    }

    #[test]
    fn test_execute_invalid_aggregated_public_key() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "x",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"aggregated-public-key\")"
        );
    }

    #[test]
    fn test_execute_invalid_sig() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "x",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"sig\")"
        );
    }

    #[test]
    fn test_execute_invalid_private_key() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "x",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"private-key\")"
        );
    }

    #[test]
    #[should_panic(expected = "the length of block vss should equal to the length of node vss")]
    fn test_execute_wrong_number_of_block_vss() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let _ = ComputeSigCommand::execute(&matches);
    }

    #[test]
    #[should_panic(expected = "the length of sig should equal to the length of node vss")]
    fn test_execute_wrong_number_of_sig() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e012103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let _ = ComputeSigCommand::execute(&matches);
    }

    #[test]
    fn test_execute_invalid_xfield() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--xfield",
            "x",
            "--block-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0bd4d89b2950241a856e6da564288743fbcc4b324f5631bb696553f365e6d957e8b0ec2d0e288215d1b561cf3c4517743e630bef13ea88c639465d5bbc22a1a9f547c16dbdacca5791321622bb12f1fd60007a77154ca36b8de432d91f6e3eeb1d658f81dad15e1bca0fa4203d0d88de7620ba79d8b24f79d0fe350d93e507f36ba19e63fadf5c9c2e43ca7898148626af65b7bf0ece9db41186b98050e04f5b0b2b2764d6afdbe57a91925a9bd778bc0433b4cdb0a9ce44969aac0c991926a447cd8c025a4f7bf5a690c2dec246628adecdee12d176db38dcbabc23bfb62132e77ee55761cf189133318d8ca95fd853557b7ddbc7114ef7c191c3a75466844d16fa8c8ec0921c23c0e897a33aa976aa77490b87f3ea7d50f6eeb7e72a8d69b6e1",
            "--block-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c63250f2db3eb32875f2ab4a29cc25edd82cac3f589765b5ab1fb0048cef49ea4ddf06f11a001e1271b212e3e3c2387c1509c511c1623368eb5540ef113219c3884eb8edbb50c6116bcde0d51973c8669cb317251b23e5e0605f11bd6b36bb8e3a33cabf430e5efda94cb837ecddf19b33e54de2f05c17807d4b129b33aaabd9260a540d7a18ce6795fe15d661d19f5e869855cbf4f26f03b976af5348941077c9cdaf0d24c14cd78a0d54b5d633da1227d353c0a7689a4a54e04ffb6310b5d8b852329c91eea9673c32002248f96bd8899e7e0b6e7edafeb86e08637f3a2c08b11eed4135071e495857bbd9ef2d5f62c3b3ede4e29e24c8cdb80285c3534cb146ad404719bcd32778a08ffc8296efc67463241f4babb8982b36cd8bfe8713e26",
            "--block-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00021ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6eed381a222dfa8172fb1afa93b0d48da11ae313ec5933330980527e476ca959d575681f8b9c3d618701533f148f9f1cc60ee54f4bd19bc1f653f59fc8572b0536d461c8454af57e4ab98b2a89561764183604661d24d33f1fe21d8f81a66899f16cddb4bc18af3cb1fe2b7b0700fa0873f9365e64b11a90ee8a2003e2ccde29b1ebb71ead55be76658b0e94847f7298ccaebf86bd95a2eb4f598a362000faee6112c7e5ddd2057e8d04e5056c4f2b725ee51cec13a6ccccf67fad81a8935669291ebd5724f71bf36e716b637a9db2f1400e9ee7693230746d98e06ad517876952d0d209734d8d10e1a9c3507a4fc4784d11c7b7bf6a8f1010af582498dfb3e8629c2ea58d8865bd32c0aeaa6e3eececf6b5fb1044ebd01eed49e2365242eb174",
            "--node-vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112734aab9f763d82eaa3cfe0792e4b8da3022f0f42b32ceb01757265fa99f29c76fd1675a7e28bf8f325b32f87e7c0c01503216f46f169ae7eebbcd7a2c0ac3f54e6660325ccf75e6b278364d1e71c48c5fcf1de97237e5cdbb2635980c0c77b1af9",
            "--node-vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce913f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1ce3573e2158dd7d16a2783265a0d1f44612fb44b24f6cabfa71e9fad736137f59e1a7bfc38def0de39f3faf29421e15c1424aa0bbe275dd0ec832fd7c34fb2f89f1cf17ad25ab75c2c124179386e18105a3d907a6f80cca43851485ce4fbdce9",
            "--node-vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce63cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140dc0f59ac7b7a5e00aa48b8cd214011edfd9706c97032a7e91207ed8ea7127c9955918c6a7dd61da49783c4013b49f7120ffa04586f9c91e5c938bcd3667442ca801b6775343b6f71791392d4ccbd84edec9cfc8c8d5f8bce817c8c39e6386ce6",
            "--node-secret-share",
            "853b7ebcfdf491f5288aa635217462fc7e0a4743cbf493e95d54f6cac2792387",
            "--aggregated-public-key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "2bebd2c65553c400ff9ed3e13ec59a0fddeefb34ccebd932db44fe63de139538c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe089003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "a4af87b6a5f9563e3a7815241cfe0099d5bad2e949b36933313b2ad44ad6d098c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe08900313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "1d733ca6f69ee87b75515666fb36672512d7cdb7173258f7c75ef8b7e763cab7c26be91145a7b67096e44bb318eb1780f4fc1630e6cde6d5705690236fbe0890023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private-key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"xfield\")"
        );
    }

    #[test]
    fn test_execute_success_xfield() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--xfield",
            "0121025700236c2890233592fcef262f4520d22af9160e3d9705855140eb2aa06c35d3",
           "--block-vss",
           "0256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f30256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f300020690cb2a3d02b81fc4fd3aebcbf8d06c95489a1afacd85ede4a90ed1e03a63b94d9b24190fce33b12eb517a7567c583a90ce2d51988b28dc0f6cd614f9320604b9c1c7ffeda2cb3a025bb887627cbfdb6b7067c4fd38a9f83cc301845b80a5c325222cc677c75453d719a8ac9a6244da6d45693d3f929ccd6c2c2ff1716ca74132b1f2b2bf09d498dbc66743dc1e0ae1c2600698fc22f108aa9de0532d7981110690cb2a3d02b81fc4fd3aebcbf8d06c95489a1afacd85ede4a90ed1e03a63b9b264dbe6f031cc4ed14ae858a983a7c56f31d2ae6774d723f09329ea06cdf62b2f14042ab1b3d483429ab1544dd9fd91397755656433718c6a05070558510c99c7d254c8cb323b2a5e340521cd7707d026ef8a5077d8f4d7c47f7c0d7a6e1411a49c47eae9a8089937cc42f06b1ad08763234cfe81ddf1da16a7ba8a0bd60405",
            "--block-vss",
            "02c4635894070e1d1b6fc669782d7efc5e62116e811970a431833975761fee89890256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f3000274af185b0f4ae72af4f6bf75a4858c4dc3a7f28752870cf80faac1d826542a5e7733c73498893e25c74d9a9b0b635c8c341b751bfe41e320fa344ab25f2595acd9f3928757c5969f3f7614ed9c0b393785d5d7690e9453e9995a3dc233285568bdb08095ab59806afd00eb315f5fe9a58a08b55351f431c6e8938c0818a12c7f59867f3c769be24296958dbe25c47084166e965996f9fe5e3117d1692205f01074af185b0f4ae72af4f6bf75a4858c4dc3a7f28752870cf80faac1d826542a5e88cc38cb6776c1da38b26564f49ca373cbe48ae401be1cdf05cbb54ca0da66831835d442a4334cd2643a0dba643e3179a00eca0d291e4e3344d71f76adff833c3194a466903b228392f5539c525e6a262748b4eb5d626d004f91f028f7667e3dd1703df47a15147a95fbe475de37dfe5d139e4ee9f2dc7d631952b35eacba56d",
            "--block-vss",
            "0377b47c58ff3e309c283296d975808918b96656d4816ea244fbfceee836f7d11b0256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f300026b9a0b482fd2f58bc5ba78762751d24c4c1622f3c392868bc005a07162a969a5a0930bdb6ae2f72d650985e8e765de785ef7bca2117039841a3dce61a1a502573b94c844e4b68c4211b2fe5052957dab66b4536e23495e3377e9be7ffe0c3ed48918270ed5f1a08df6002c6d94d8668943888a7e4e4df0b28e6b8516e7e31e4513922442e3008c9677541c96b3f95d535c7398d77c987d6de0e3b41a875cb25f6b9a0b482fd2f58bc5ba78762751d24c4c1622f3c392868bc005a07162a969a55f6cf424951d08d29af67a17189a2187a108435dee8fc67be5c2319d5e5af9d8ffaf64a2b639282ac7b2e7550d164bb86912c410b8fec9c0b2aed33382e8cdd04e4c754bc0d59173198eea0f1b883a6baf9ecc3ca1b903a61219d1e2eb7d3440aff3e8df0a8b66d5a39c01b3689dc2bc2e70d4f21e773b0e5539c87cabc47444",
            "--node-vss",
            "0256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f30256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f3000256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f3a9a238f2f935deca950a2a2133a9a6773012bec36c9f37de8955781b5839575ce540d2c7af035bc9643ffaccf9e4f82e2f86e79d762a0a2645b346db0cd201c05482b0a18cf0f9d5c630023d808dc54a9e24ac884f4849b4a2e7cd76c53313f3261e1777e2bad13b1799f3ee3dcf89d485e7a3fade4203bd05088789582cb47956b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f3a9a238f2f935deca950a2a2133a9a6773012bec36c9f37de8955781b5839575ce540d2c7af035bc9643ffaccf9e4f82e2f86e79d762a0a2645b346db0cd201c05482b0a18cf0f9d5c630023d808dc54a9e24ac884f4849b4a2e7cd76c53313f3261e1777e2bad13b1799f3ee3dcf89d485e7a3fade4203bd05088789582cb479",
            "--node-vss",
            "02c4635894070e1d1b6fc669782d7efc5e62116e811970a431833975761fee89890256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f30002c4635894070e1d1b6fc669782d7efc5e62116e811970a431833975761fee89895eefc5bae0eeeebdf8614d74a51a23b9d3bce95294a1de04901726b54a73e3b4db2951648e5d0ed3b8ac1690427a4b8157c3626db147f5e10af6636dada7759e56fc455d5804ac5e41980ab346b0ac35cea254a41e94d21d45fd64d62f7f391956897da644dde3f4888797c41e74dce07fb661ce671a3adf402af463bcb31e41c4635894070e1d1b6fc669782d7efc5e62116e811970a431833975761fee89895eefc5bae0eeeebdf8614d74a51a23b9d3bce95294a1de04901726b54a73e3b4db2951648e5d0ed3b8ac1690427a4b8157c3626db147f5e10af6636dada7759e56fc455d5804ac5e41980ab346b0ac35cea254a41e94d21d45fd64d62f7f391956897da644dde3f4888797c41e74dce07fb661ce671a3adf402af463bcb31e41",
            "--node-vss",
            "0377b47c58ff3e309c283296d975808918b96656d4816ea244fbfceee836f7d11b0256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f3000277b47c58ff3e309c283296d975808918b96656d4816ea244fbfceee836f7d11b110adf8789d05e65dd341359cd2714b08208e7ce017d3e0bf71d6eaa0ca9c76f1063e7d72914f0e98e1b378f52d0d4619f0ba0a4ca6d27cedec328b0483483c28ea4984f9d157515144c750b743172bd7c9d7b278a82a1625086b241f22071a6f7c3a69d6e8119fa2af1d79aad5967f72977e7649e3227789b6f5f4dbaede03777b47c58ff3e309c283296d975808918b96656d4816ea244fbfceee836f7d11b110adf8789d05e65dd341359cd2714b08208e7ce017d3e0bf71d6eaa0ca9c76f1063e7d72914f0e98e1b378f52d0d4619f0ba0a4ca6d27cedec328b0483483c28ea4984f9d157515144c750b743172bd7c9d7b278a82a1625086b241f22071a6f7c3a69d6e8119fa2af1d79aad5967f72977e7649e3227789b6f5f4dbaede037",
            "--sig",
            "5eb574266ead78a0616089c5e01a2c650c32422680d48e4428b83543834714437e5d309fe0d0745e18bd8984eefca234da8af200b1f7a7e9dd168bbdea56d8680256b1bf5532d6627e763cd694d432dd061132ddfb528d692e23fecf6cca4c20f3",
            "--sig",
            "df8a7ab4be43ece5b0f8381078afebdc2e91020b499b78b56fe9e860fb1c099f7e5d309fe0d0745e18bd8984eefca234da8af200b1f7a7e9dd168bbdea56d86802c4635894070e1d1b6fc669782d7efc5e62116e811970a431833975761fee8989",
            "--sig","605f81430dda612b008fe65b1145ab549640e5096319c2eaf7493cf1a2babdba7e5d309fe0d0745e18bd8984eefca234da8af200b1f7a7e9dd168bbdea56d8680377b47c58ff3e309c283296d975808918b96656d4816ea244fbfceee836f7d11b",
            "--node-secret-share",
            "746b3bbb9619cf29cb13634d099dcead746710473445c5d920d07cadff9771b0",
            "--aggregated-public-key",
            "0303a8d919266c95407e8aa247b058d510e6286ddb9ba73c7a283edc67bb11ed1e",
            "--private-key",
            "KzJbxJCY4FZX7Ki8tsg5V9dAsxhgGBWAbQEcakByuHH2Y7KyrvZZ"
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert!(response.is_ok());
    }
}
