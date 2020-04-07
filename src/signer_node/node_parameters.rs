use super::utils::sender_index;
use crate::crypto::multi_party_schnorr::{Parameters, SharedKeys};
use crate::crypto::vss::Vss;
use crate::federation::{Federation, Federations};
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::{SharedSecret, SharedSecretMap};
use bitcoin::{Address, PublicKey};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use std::convert::TryInto;
use std::sync::Arc;

pub struct NodeParameters<T: TapyrusApi> {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u8,
    pub rpc: std::sync::Arc<T>,
    pub address: Address,
    /// Own Signer ID. Actually it is signer own public key.
    pub signer_id: SignerID,
    pub self_node_index: usize,
    pub round_duration: u64,
    pub skip_waiting_ibd: bool,
    pub node_vss: Vec<Vss>,
    federations: Federations,
}

impl<T: TapyrusApi> NodeParameters<T> {
    pub fn new(
        to_address: Address,
        pubkey_list: Vec<PublicKey>,
        threshold: u8,
        public_key: PublicKey,
        node_vss: Vec<Vss>,
        rpc: T,
        round_duration: u64,
        skip_waiting_ibd: bool,
        federations: Federations,
    ) -> NodeParameters<T> {
        let signer_id = SignerID { pubkey: public_key };

        let mut pubkey_list = pubkey_list;
        NodeParameters::<T>::sort_publickey(&mut pubkey_list);

        let self_node_index = sender_index(&signer_id, &pubkey_list);
        NodeParameters {
            pubkey_list,
            threshold,
            rpc: Arc::new(rpc),
            address: to_address,
            signer_id,
            self_node_index,
            round_duration,
            skip_waiting_ibd,
            node_vss,
            federations,
        }
    }

    fn get_federation_by_block_height(&self, block_height: u64) -> &Federation {
        self.federations.get_by_block_height(block_height)
    }

    pub fn get_signer_id_by_index(&self, index: usize) -> SignerID {
        SignerID {
            pubkey: self.pubkey_list[index].clone(),
        }
    }

    pub fn sharing_params(&self) -> Parameters {
        let t = (self.threshold - 1 as u8).try_into().unwrap();
        let n: usize = (self.pubkey_list.len() as u8).try_into().unwrap();
        Parameters {
            threshold: t,
            share_count: n.clone(),
        }
    }

    pub fn sort_publickey(pubkeys: &mut Vec<PublicKey>) {
        pubkeys.sort_by(|a, b| {
            let a = a.key.serialize();
            let b = b.key.serialize();
            Ord::cmp(&a[..], &b[..])
        });
    }

    /// Returns Map collection of received shares from all each signers in Key Generation Protocol
    pub fn node_shared_secrets(&self) -> SharedSecretMap {
        let mut secret_shares = SharedSecretMap::new();
        for vss in &self.node_vss {
            secret_shares.insert(
                SignerID {
                    pubkey: vss.sender_public_key,
                },
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: ShamirSecretSharing {
                            threshold: (self.threshold - 1) as usize,
                            share_count: self.node_vss.len(),
                        },
                        commitments: vss
                            .positive_commitments
                            .iter()
                            .map(|i| i.to_point())
                            .collect(),
                    },
                    secret_share: vss.positive_secret,
                },
            );
        }
        secret_shares
    }

    /// Returns an aggregated share of the node.
    pub fn node_secret_share(&self) -> SharedKeys {
        let secret_shares = self.node_shared_secrets();

        let shared_keys =
            Sign::verify_vss_and_construct_key(&secret_shares, &(self.self_node_index + 1))
                .expect("invalid vss");
        shared_keys
    }
}

#[cfg(test)]
mod tests {
    use crate::signer_node::NodeParameters;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::rpc::MockRpc;
    use bitcoin::PublicKey;
    use std::str::FromStr;

    #[test]
    fn test_sort_publickey() {
        let mut pubkeys = TEST_KEYS.pubkeys();
        NodeParameters::<MockRpc>::sort_publickey(&mut pubkeys);

        assert_eq!(
            pubkeys,
            vec![
                PublicKey::from_str(
                    "02472012cf49fca573ca1f63deafe59df842f0bbe77e9ac7e67b211bb074b72506",
                )
                .unwrap(),
                PublicKey::from_str(
                    "02785a891f323acd6cef0fc509bb14304410595914267c50467e51c87142acbb5e",
                )
                .unwrap(),
                PublicKey::from_str(
                    "02ce7edc292d7b747fab2f23584bbafaffde5c8ff17cf689969614441e0527b900",
                )
                .unwrap(),
                PublicKey::from_str(
                    "02d111519ba1f3013a7a613ecdcc17f4d53fbcb558b70404b5fb0c84ebb90a8d3c",
                )
                .unwrap(),
                PublicKey::from_str(
                    "03831a69b8009833ab5b0326012eaf489bfea35a7321b1ca15b11d88131423fafc",
                )
                .unwrap(),
            ]
        );
    }
}
