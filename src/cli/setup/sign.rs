use crate::blockdata::Block;
use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::crypto::multi_party_schnorr::LocalSig;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::signer_node::BidirectionalSharedSecretMap;
use crate::signer_node::SharedSecret;

use bitcoin::{PrivateKey, PublicKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use std::fmt;
use std::str::FromStr;

pub struct SignResponse {
    local_sig: LocalSig,
    public_key: PublicKey,
}

impl SignResponse {
    fn new(local_sig: LocalSig, public_key: PublicKey) -> Self {
        SignResponse {
            local_sig: local_sig,
            public_key: public_key,
        }
    }
}

impl Response for SignResponse {}

impl fmt::Display for SignResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:0>64}{:0>64}{}",
            self.local_sig.gamma_i.to_big_int().to_hex(),
            self.local_sig.e.to_big_int().to_hex(),
            hex::encode(&self.public_key.key.serialize()[..]),
        )
    }
}

pub struct SignCommand {}

impl<'a> SignCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let private_key: PrivateKey = matches
            .value_of("private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("private_key".to_string()))?;

        let threshold: usize = matches
            .value_of("threshold")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error::InvalidArgs("threshold".to_string()))?;

        let block: Block = matches
            .value_of("block")
            .and_then(|s| hex::decode(s).ok())
            .map(|hex| Block::new(hex))
            .ok_or(Error::InvalidArgs("block".to_string()))?;

        let node_secret_share: FE = matches
            .value_of("node_secret_share")
            .and_then(|s| BigInt::from_str_radix(s, 16).ok())
            .map(|i| ECScalar::from(&i))
            .ok_or(Error::InvalidArgs("node_secret_share".to_string()))?;

        let aggregated_public_key: PublicKey = matches
            .value_of("aggregated_public_key")
            .and_then(|hex| PublicKey::from_str(hex).ok())
            .ok_or(Error::InvalidArgs("aggregated_public_key".to_string()))?;

        let block_vss_vec: Vec<Vss> = matches
            .values_of("block_vss")
            .ok_or(Error::InvalidArgs("block_vss".to_string()))?
            .map(|s| Vss::from_str(s).map_err(|_| Error::InvalidArgs("block_vss".to_string())))
            .collect::<Result<Vec<Vss>, _>>()?;

        let mut public_keys: Vec<PublicKey> = block_vss_vec
            .iter()
            .map(|vss| vss.sender_public_key)
            .collect();
        public_keys.sort();

        let index = index_of(&private_key, &public_keys);

        let params = ShamirSecretSharing {
            threshold: (threshold - 1) as usize,
            share_count: public_keys.len(),
        };
        let mut shared_block_secrets = BidirectionalSharedSecretMap::new();
        for vss in block_vss_vec.iter() {
            shared_block_secrets.insert(
                SignerID {
                    pubkey: vss.sender_public_key,
                },
                (
                    SharedSecret {
                        secret_share: vss.positive_secret,
                        vss: VerifiableSS {
                            parameters: params.clone(),
                            commitments: vss
                                .positive_commitments
                                .iter()
                                .map(|c| c.to_point())
                                .collect(),
                        },
                    },
                    SharedSecret {
                        secret_share: vss.negative_secret,
                        vss: VerifiableSS {
                            parameters: params.clone(),
                            commitments: vss
                                .negative_commitments
                                .iter()
                                .map(|c| c.to_point())
                                .collect(),
                        },
                    },
                ),
            );
        }

        let bytes: Vec<u8> = aggregated_public_key.key.serialize_uncompressed().to_vec();
        let point = GE::from_bytes(&bytes[1..]).expect("failed to convert to point");
        let priv_shared_keys = SharedKeys {
            y: point,
            x_i: node_secret_share,
        };

        let (_, _, local_sig) = Vss::create_local_sig_from_shares(
            &priv_shared_keys,
            index,
            &shared_block_secrets,
            &block,
        )?;

        let secp = secp256k1::Secp256k1::new();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        Ok(Box::new(SignResponse::new(local_sig, public_key)))
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("sign").args(&[
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
            Arg::with_name("block_vss")
                .long("block_vss")
                .required(true)
                .multiple(true)
                .takes_value(true)
                .help("the block VSSs generated by tapyrus-setup createblockvss command"),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00026f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b446f5671fe2ec0aad0377c88ecc53b7518c9cad08383248ee5f07d4c18858c497d12ae6c0ba5133968eb6c133bd8d0546a284aaf86853128eebd74c6416c97467511c67078abcf4cdf88662fd94088c89525572d38a79fd16c49fbfa1fab43eaeb45d88b4ea3b2fd06d01d3a18e3fec209face7a8a2c0b0ef9f5912645ad0456f6f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b4b90a98e01d13f552fc88377133ac48ae736352f7c7cdb711a0f82b3d77a73798f3d97934f9d1980214a33adeeffc5c306470dc29fda365f17b8a1c5e30b6fad35b49a86672a5acc38dfc7ea022d65913077066c538dcef884c34969ae88598da62b895aafcbd3b4c4b8f49522946ab949e0755159980da5d303da0231da3fa03",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "ed4833a378f368c3abd701bffe3a4e7982ac5f7facf9d9bec4ff07be88508123",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = SignCommand::execute(&matches);
        assert!(response.is_ok());
    }

    #[test]
    fn test_execute_invalid_threshold() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "x",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00026f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b446f5671fe2ec0aad0377c88ecc53b7518c9cad08383248ee5f07d4c18858c497d12ae6c0ba5133968eb6c133bd8d0546a284aaf86853128eebd74c6416c97467511c67078abcf4cdf88662fd94088c89525572d38a79fd16c49fbfa1fab43eaeb45d88b4ea3b2fd06d01d3a18e3fec209face7a8a2c0b0ef9f5912645ad0456f6f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b4b90a98e01d13f552fc88377133ac48ae736352f7c7cdb711a0f82b3d77a73798f3d97934f9d1980214a33adeeffc5c306470dc29fda365f17b8a1c5e30b6fad35b49a86672a5acc38dfc7ea022d65913077066c538dcef884c34969ae88598da62b895aafcbd3b4c4b8f49522946ab949e0755159980da5d303da0231da3fa03",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "ed4833a378f368c3abd701bffe3a4e7982ac5f7facf9d9bec4ff07be88508123",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = SignCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"threshold\")"
        );
    }

    #[test]
    fn test_execute_invalid_block() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "2",
            "--block",
            "x",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00026f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b446f5671fe2ec0aad0377c88ecc53b7518c9cad08383248ee5f07d4c18858c497d12ae6c0ba5133968eb6c133bd8d0546a284aaf86853128eebd74c6416c97467511c67078abcf4cdf88662fd94088c89525572d38a79fd16c49fbfa1fab43eaeb45d88b4ea3b2fd06d01d3a18e3fec209face7a8a2c0b0ef9f5912645ad0456f6f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b4b90a98e01d13f552fc88377133ac48ae736352f7c7cdb711a0f82b3d77a73798f3d97934f9d1980214a33adeeffc5c306470dc29fda365f17b8a1c5e30b6fad35b49a86672a5acc38dfc7ea022d65913077066c538dcef884c34969ae88598da62b895aafcbd3b4c4b8f49522946ab949e0755159980da5d303da0231da3fa03",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "ed4833a378f368c3abd701bffe3a4e7982ac5f7facf9d9bec4ff07be88508123",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = SignCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"block\")"
        );
    }

    #[test]
    fn test_execute_invalid_block_vss() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "x",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "ed4833a378f368c3abd701bffe3a4e7982ac5f7facf9d9bec4ff07be88508123",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = SignCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"block_vss\")"
        );
    }

    #[test]
    fn test_execute_invalid_node_secret_share() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00026f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b446f5671fe2ec0aad0377c88ecc53b7518c9cad08383248ee5f07d4c18858c497d12ae6c0ba5133968eb6c133bd8d0546a284aaf86853128eebd74c6416c97467511c67078abcf4cdf88662fd94088c89525572d38a79fd16c49fbfa1fab43eaeb45d88b4ea3b2fd06d01d3a18e3fec209face7a8a2c0b0ef9f5912645ad0456f6f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b4b90a98e01d13f552fc88377133ac48ae736352f7c7cdb711a0f82b3d77a73798f3d97934f9d1980214a33adeeffc5c306470dc29fda365f17b8a1c5e30b6fad35b49a86672a5acc38dfc7ea022d65913077066c538dcef884c34969ae88598da62b895aafcbd3b4c4b8f49522946ab949e0755159980da5d303da0231da3fa03",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "x",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = SignCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"node_secret_share\")"
        );
    }

    #[test]
    fn test_execute_invalid_aggregated_public_key() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00026f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b446f5671fe2ec0aad0377c88ecc53b7518c9cad08383248ee5f07d4c18858c497d12ae6c0ba5133968eb6c133bd8d0546a284aaf86853128eebd74c6416c97467511c67078abcf4cdf88662fd94088c89525572d38a79fd16c49fbfa1fab43eaeb45d88b4ea3b2fd06d01d3a18e3fec209face7a8a2c0b0ef9f5912645ad0456f6f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b4b90a98e01d13f552fc88377133ac48ae736352f7c7cdb711a0f82b3d77a73798f3d97934f9d1980214a33adeeffc5c306470dc29fda365f17b8a1c5e30b6fad35b49a86672a5acc38dfc7ea022d65913077066c538dcef884c34969ae88598da62b895aafcbd3b4c4b8f49522946ab949e0755159980da5d303da0231da3fa03",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "ed4833a378f368c3abd701bffe3a4e7982ac5f7facf9d9bec4ff07be88508123",
            "--aggregated_public_key",
            "x",
            "--private_key",
            "L2hmApEYQBQo81RLJc5MMwo6ZZywnfVzuQj6uCfxFLaV2Yo2pVyq",
        ]);
        let response = SignCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"aggregated_public_key\")"
        );
    }

    #[test]
    fn test_execute_invalid_private_key() {
        let matches = SignCommand::args().get_matches_from(vec![
            "sign",
            "--threshold",
            "2",
            "--block",
            "010000000000000000000000000000000000000000000000000000000000000000000000c0d6961ad2819f74eb6d085f04f9cceb0a9a6d5c153fd3c39fc47c3ca0bb548f85fbd09a5f7d8ac4c9552e52931ef6672984f64e52ad6d05d1cdb18907da8527db317c5e2103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c00010100000001000000000000000000000000000000000000000000000000000000000000000000000000222103addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1cffffffff0100f2052a010000001976a914a15f16ea2ba840d178e4c19781abca5f4fb1b4c288ac00000000",
            "--block_vss",
            "03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d03b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d00026f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b446f5671fe2ec0aad0377c88ecc53b7518c9cad08383248ee5f07d4c18858c497d12ae6c0ba5133968eb6c133bd8d0546a284aaf86853128eebd74c6416c97467511c67078abcf4cdf88662fd94088c89525572d38a79fd16c49fbfa1fab43eaeb45d88b4ea3b2fd06d01d3a18e3fec209face7a8a2c0b0ef9f5912645ad0456f6f10601a7230d999cc50485c5971a26344569f0116b45fc8810dc0a77612f9b4b90a98e01d13f552fc88377133ac48ae736352f7c7cdb711a0f82b3d77a73798f3d97934f9d1980214a33adeeffc5c306470dc29fda365f17b8a1c5e30b6fad35b49a86672a5acc38dfc7ea022d65913077066c538dcef884c34969ae88598da62b895aafcbd3b4c4b8f49522946ab949e0755159980da5d303da0231da3fa03",
            "--block_vss",
            "0313f2a73541e6d55a75a80a6da819885c6ed6e56ecff19f5e928c4ea202ca7c9003b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d000206112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d1fc53921eba789fba31b11bb60bc4825b2fe0b82e9120469555750182345972d9a182b45c8d5161f0d4b46724afbd0bd4aff320101f98f7180cce1671498cd69971b0f5efd1d8df8047a23f7ad46807c66477109523c405c6e2f9049d30920de16a1ca5c000ef014c784632159053a990867713e7e4c6fd1482c4cc609a83dd2d06112e310202813b404945291159fdda6d1c3d7467b744f2da1138a6a815d2d103ac6de145876045ce4ee449f43b7da4d01f47d16edfb96aaa8afe7ccba68956e53cf376e1142706dbada47f457c0aaca9c0ab13f030b2d09c200221596628565c824dd48152b1ea62d565bbbc300dd9c2e295edcbc20ee7168784864c2fc2327a20e535227bfd8bd359e3d3e42d96ff05a29142c6ae19582c001aadd0c84970",
            "--block_vss",
            "023cb7d6326e33332d04d026be1a04cdaf084703d8dc75322182d8fb314a03a87703b8ad9e3271a20d5eb2b622e455fcffa5c9c90e38b192772b2e1b58f6b442e78d0002b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc61585653ecbe0a83784becfcee6dd2589c98e7700ee3a35562d1817efa77e69f73c81ed9d839edfa3266cdf26136c2e18280f9e3c1bf61491ef07c9154850f7df75d146095c80bc3717e5cf7de5a690c55c46693a4dbb2da3621a990feadb726c4cda7068ee2026396e7fa3caa82cdba3e8f3b6c8ddb536070e1194496d1023a2b338ba467e1c36a671919abb48dd56c9529585392d75365fe50a717cb1ad2cc6ea7a9ac1341f57c87b4130311922da76367188ff11c5caa9d2e7e80f5881923855ac65a6ab8bac296ca59cc64b236dd4d8068c80114953b7f74a463c4cdc26eb515884f7c81fedf7d9a366a6801e14d854639b1ea582712e1ff29e78d9f931000bec4715b84298bf6f568db1ed02cbc70b7b5d2af36e562ea9f1621e238d8dbe",
            "--node_secret_share",
            "ed4833a378f368c3abd701bffe3a4e7982ac5f7facf9d9bec4ff07be88508123",
            "--aggregated_public_key",
            "03addb2555f37abf8f28f11f498bec7bd1460e7243c1813847c49a7ae326a97d1c",
            "--private_key",
            "x",
        ]);
        let response = SignCommand::execute(&matches);
        assert_eq!(
            format!("{}", response.err().unwrap()),
            "InvalidArgs(\"private_key\")"
        );
    }
}
