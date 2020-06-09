use crate::crypto::vss::Vss;
use crate::net::SignerID;
use crate::signer_node::BidirectionalSharedSecretMap;
use crate::signer_node::SharedSecret;
use crate::signer_node::SharedSecretMap;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use tapyrus::{PrivateKey, PublicKey};

pub mod aggregate;
pub mod compute_sig;
pub mod create_block_vss;
pub mod create_key;
pub mod create_node_vss;
pub mod sign;
pub mod traits;

pub fn index_of(private_key: &PrivateKey, public_keys: &Vec<PublicKey>) -> usize {
    let secp = tapyrus::secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_private_key(&secp, private_key);
    let pos = public_keys
        .iter()
        .position(|pk| pk == &public_key)
        .expect("private_key or public_keys is invalid.");
    pos + 1
}

pub fn vss_to_shared_secret_map(
    node_vss_vec: &Vec<Vss>,
    params: &ShamirSecretSharing,
) -> SharedSecretMap {
    let mut shared_secrets = SharedSecretMap::new();
    for node_vss in node_vss_vec {
        shared_secrets.insert(
            SignerID {
                pubkey: node_vss.sender_public_key,
            },
            SharedSecret {
                vss: VerifiableSS {
                    parameters: params.clone(),
                    commitments: node_vss
                        .positive_commitments
                        .iter()
                        .map(|c| c.to_point())
                        .collect(),
                },
                secret_share: node_vss.positive_secret,
            },
        );
    }
    shared_secrets
}

pub fn vss_to_bidirectional_shared_secret_map(
    block_vss_vec: &Vec<Vss>,
    params: &ShamirSecretSharing,
) -> BidirectionalSharedSecretMap {
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
    shared_block_secrets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tapyrus::{PrivateKey, PublicKey};

    #[test]
    fn test_index_of() {
        let private_key =
            PrivateKey::from_wif("KwUKaA3KgtRhCsioNWZQfC6Nd6vPNTXwgmqcStewZ3KdonmP3k43").unwrap();
        let public_keys = vec![
            "023092e0fad6f42a2f456f5a891d8ea868393ca4308fef0f29388a1c5687d5860e",
            "03abdc3e2d64fb3e9ceeaf7d0f272c14c36793dfb862018c34a6ac5dfe0c02860e",
            "03d10d42715a8c7e6c93fac9336bcb5b286e827e766594e4d166b4894b805236a7",
        ]
        .iter()
        .map(|key| PublicKey::from_str(key).unwrap())
        .collect();

        assert_eq!(index_of(&private_key, &public_keys), 2);
    }
}
