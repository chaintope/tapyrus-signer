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
use crate::rpc::Rpc;
use crate::sign::Sign;
use crate::signer_node::NodeParameters;

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
            .and_then(|s| BigInt::from_str_radix(s, 16).ok())
            .map(|i| ECScalar::from(&i))
            .ok_or(Error::InvalidArgs("node_secret_share".to_string()))?;

        let block: Block = matches
            .value_of("block")
            .and_then(|s| hex::decode(s).ok())
            .map(|hex| Block::new(hex))
            .ok_or(Error::InvalidArgs("block".to_string()))?;

        let node_vss_vec: Vec<Vss> = matches
            .values_of("node_vss")
            .ok_or(Error::InvalidArgs("node_vss".to_string()))?
            .map(|s| Vss::from_str(s).map_err(|_| Error::InvalidArgs("node_vss".to_string())))
            .collect::<Result<Vec<Vss>, _>>()?;

        let block_vss_vec: Vec<Vss> = matches
            .values_of("block_vss")
            .ok_or(Error::InvalidArgs("block_vss".to_string()))?
            .map(|s| Vss::from_str(s).map_err(|_| Error::InvalidArgs("block_vss".to_string())))
            .collect::<Result<Vec<Vss>, _>>()?;

        let keyed_local_sigs: Vec<(LocalSig, PublicKey)> = matches
            .values_of("sig")
            .ok_or(Error::InvalidArgs("local_sig is invalid".to_string()))?
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
                .takes_value(true)
                .help("private key of this signer with an extend WIF format"),
            Arg::with_name("threshold")
                .long("threshold")
                .required(true)
                .takes_value(true)
                .help("the minimum number of signers required to sign block"),
            Arg::with_name("block")
                .long("block")
                .required(true)
                .takes_value(true)
                .help("block to be signed as a hex string format"),
            Arg::with_name("node_secret_share")
                .long("node_secret_share")
                .required(true)
                .takes_value(true)
                .help("secret key share of the signers with a hex string format"),
            Arg::with_name("aggregated_public_key")
                .long("aggregated_public_key")
                .required(true)
                .takes_value(true)
                .help("aggregated public key of all signers"),
            Arg::with_name("node_vss")
                .long("node_vss")
                .required(true)
                .multiple(true)
                .takes_value(true)
                .help("the node VSSs generated by tapyrus-setup createnodevss command"),
            Arg::with_name("block_vss")
                .long("block_vss")
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
    fn test_execute() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
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
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
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
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
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
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "x",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"block_vss\")"
        );
    }

    #[test]
    fn test_execute_invalid_node_vss() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "x",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"node_vss\")"
        );
    }

    #[test]
    fn test_execute_invalid_node_secret_share() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "x",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"node_secret_share\")"
        );
    }

    #[test]
    fn test_execute_invalid_aggregated_public_key() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "x",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"aggregated_public_key\")"
        );
    }

    #[test]
    fn test_execute_invalid_sig() {
        let matches = ComputeSigCommand::args().get_matches_from(vec![
            "computesig",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "x",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
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
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
            "x",
        ]);
        let response = ComputeSigCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"private_key\")"
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
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "b8c3d6ab3d1619075af261a2855431a823b0a1dab2207a738f4b2697ea3458c1ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a188903b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
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
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba111d50dc116a12e63b4bbbee4361e2db726941f7a87e6535818759651e9b2ac5ca89840e74b6928bf2a970cc02ce748c3d2c29450ffd1a5e8467d39ff8042c9a91b3f35a75f2a28c00d43188eee3b6ae7e3c9082d1ae8d078ea4540359bf2eeeea9ebd95a2c7db5651bf45dc2307db03a5f04533759b824b499b14f2525bd5c760ea874da6f110fc45b53ce0ea3a71ccef2ea365cfa60afacc85c054f60714ba11e2af23ee95ed19c4b44411bc9e1d248d96be0857819aca7e78a69ae064d536657beac9e314ecd55d4abf04b338d52a693d35d9d64caf0c4fbf38766f961c6e082375c2268d21a5a68e2699880bb2f228b664ea4aa35ad8dabd29157f70cb3677c93555ad0c90b24646260043619578584dec15900b91f36ec82491d1e3d86c26",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd674bcf2204094a8bdc2ef01f32615c22b95de894347ea095e9b811ba38d6e57304ba07ed3a9bfcb0605a9bab42424d8e4a3c91d5f0f36bba4698954bdb2e9c527ecb544af870a90dd5905eda0c40d2ff62004a1881b0c1762d38d9e595b1ceba8a7a2e1f7dd885077f033b79d30a4b8a613c8d8a5629cc2caf4d731c737ff53e4e285ea8d57751ee35301b570b83db1fff3c6a8a887457d71531754c8bf413cd68b430ddfbf6b57423d10fe0cd9ea3dd46a2176bcb815f6a1647ee45b7291a4ff5203a2d05a956301b8a7c8241bf1f0754e462525b0d95af50b09655a419f8a116dc71eb43ca508b6ce3df12474371b1c11cfc6013691fd749b14b303d102af968741f084ba1ed15f11c69207a25e87a56dc1496a7866f4871e0f404ba0b981d8",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002a80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c4147201075c9166e35f9ab48f6a976276a3060f58c89995fa0bddf5f3c9e35e87a44de0b02cc41dac6716e790ae2f76487c624e66e96d9056a9be8f8815b4cdd75ce1b546730ecdbb8b32d15b6ac481a1ed25a034a2dfb69eef00ed07b315f8976dea3dc1826f675d88490f09dde53ad1869af24bdc52a7a8db06851ba633f1f1da80ba38c8587f8d0e75c63785cc47e5b933311f80a916c1cc7a21eeabb9a0c41b8dfef8a36e991ca0654b7095689d895cf9f0a737666a05f4220a0c261ca13b5ce4ac9611111e376e1b181b9c1917b1896ea9688d4893c1f8ada31c702477325e8873f0d47c822d6106e46c77a3051384a250f0cdbb11647015d71f0c5e0b031446227b7b68460796b28b26bb257acc2cb34aa0fd5e7725438a1e5e599020c5c",
            "--node_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dcb8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d1bb2811fe36fa9e15b7afc0ecdb4c51cad86c2c9135607f38e4ae581983112732421588b63a29574cf49000bc8323d53f6cc4cc60eae7a19c574bd51471db9c7b97fb76aef4c832cbe46908d8802e3ff253975530e1b9f6a24e3dfaa12ce35434e316308497e7722055ef867f8ab5a2a8dcac44a08d932026355edf88d0ea8dc",
            "--node_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000213f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa13f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90adbd69de8655fcc6ead8e771f9f31ead7a431e543bf8ac8d921c80ab301bc8d1f83485ef4f180852c443883d50db4faa54b162a5fe72a51330c7a09652a77ded377e0f79394dd0327c02ca647c9fe7b26487a7b4d2325d690d9ee9acad6b53fd9a90eb3d56e22bcfdca896c3c662a2f9ef6f86a82959fe28743ef9ab6c5215fa",
            "--node_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b3cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877be6e3e5cdfc8877c9f9b1a0bbee781019c55098025b03fcede5e4947d16f6140fca1c1be0aa25946c092136d9e3bed3a08a6e02e94db9207298811214687a359f82baca39403ce9cb798695d48c734fb11e47f32412325b9bff88de3031460736399e6b2c0084a3dc943a12cf2259691476ef12fa847633d5acacabdbc18f45b",
            "--node_secret_share",
            "4c5c34f86068ed2fab4b3058b13393b709fa5f3b2b31f32c728d53d4e54371f0",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--sig",
            "0a01de256ebeee68c0615bb88f8e8aad9e012cfd1e05a719b16a3dcf141ad0c9ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a18890313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c90",
            "--sig",
            "5b3fe59fa067c3ca25d055ce99c8e3b1d3009506393373fb935bb3930e378a12ae8305b68c0eac99283d69907b4dac183546a17ac89395f8bced3073476a1889023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a877",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let _ = ComputeSigCommand::execute(&matches);
    }
}
