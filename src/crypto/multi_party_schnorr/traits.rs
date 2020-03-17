use secp256k1::{constants, SecretKey};
use std::ops::Deref;

pub enum Error {
    VerifyVSS,
    VerifyLocalSig,
}

pub type Message = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Secret([u8; 32]);

impl From<SecretKey> for Secret {
    fn from(seckey: SecretKey) -> Self {
        let mut data = [0u8; constants::SECRET_KEY_SIZE];
        data.copy_from_slice(&seckey[..]);
        Secret(data)
    }
}

/// The schnorr signature what the distributed signing scheme produce finally
pub struct Signature {
    /// R.x
    pub r_x: [u8; 32],
    /// sigma
    pub sigma: [u8; 32],
}

pub mod key_generation_protocol {
    use crate::crypto::multi_party_schnorr::traits::{Error, Secret};
    use secp256k1::{PublicKey, SecretKey};
    use std::collections::HashSet;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct NodeVSS {
        pub sender_pubkey: PublicKey,
        pub receiver_pubkey: PublicKey,
        pub commitments: Vec<PublicKey>,
        pub secret: Secret,
    }

    /// Struct for a shared secret and an aggregated public key
    #[derive(Clone, Debug)]
    pub struct NodeShare {
        /// Aggregated Public Key
        pub aggregated_pubkey: PublicKey,
        /// Secret share for a signer
        pub secret_share: Secret,
    }

    pub trait KeyGenerationProtocol {
        fn create_node_vss(
            node_private_key: &SecretKey,
            signer_keys: &Vec<PublicKey>,
            threshold: usize,
        ) -> HashSet<NodeVSS>;
        fn verify_node_vss(vss: &NodeVSS) -> Result<(), Error>;
        fn aggregate_node_vss(vss_set: &HashSet<NodeVSS>) -> NodeShare;
    }
}

pub mod signature_issuing_protocol {
    use crate::crypto::multi_party_schnorr::traits::key_generation_protocol::{NodeShare, NodeVSS};
    use crate::crypto::multi_party_schnorr::traits::{Error, Message, Secret, Signature};
    use secp256k1::{PublicKey, SecretKey};
    use std::collections::HashSet;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct BlockVSS {
        pub sender_pubkey: PublicKey,
        pub receiver_pubkey: PublicKey,
        pub positive_commitments: Vec<PublicKey>,
        pub positive_secret: Secret,
        pub negative_commitments: Vec<PublicKey>,
        pub negative_secret: Secret,
    }

    /// The Struct for a shared secret and an aggregated public key
    #[derive(Clone, Debug)]
    pub struct BlockShare {
        /// Aggregated Public Key
        pub aggregated_pubkey: PublicKey,
        /// Secret share for a signer
        pub positive_secret_share: Secret,
        /// Secret share for a signer
        pub negative_secret_share: Secret,
    }

    /// The Signature
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct LocalSig {
        pub signer_pubkey: PublicKey,
        pub gamma_i: Secret,
    }

    pub trait SignatureIssuingProtocol {
        fn create_block_vss(signer_keys: &Vec<PublicKey>, threshold: usize) -> HashSet<BlockVSS>;
        fn verify_block_vss(vss: &BlockVSS) -> Result<(), Error>;
        fn aggregate_block_vss(vss_set: &HashSet<BlockVSS>) -> BlockShare;
        fn create_local_sig(
            message: &Message,
            node_share: &NodeShare,
            block_share: &BlockShare,
        ) -> LocalSig;
        fn verify_local_sig(
            local_sig: &LocalSig,
            node_vss_set: &HashSet<NodeVSS>,
            block_vss_set: &HashSet<BlockVSS>,
        ) -> Result<(), Error>;
        fn compute_final_signature(
            local_sigs: &HashSet<LocalSig>,
            threshold: usize,
        ) -> Result<Signature, Error>;
    }
}
