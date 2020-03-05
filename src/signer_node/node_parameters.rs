use super::utils::sender_index;
use crate::crypto::multi_party_schnorr::Parameters;
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use bitcoin::{Address, PrivateKey, PublicKey};
use std::convert::TryInto;
use std::sync::Arc;

pub struct NodeParameters<T: TapyrusApi> {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u8,
    pub private_key: PrivateKey,
    pub rpc: std::sync::Arc<T>,
    pub address: Address,
    /// Own Signer ID. Actually it is signer own public key.
    pub signer_id: SignerID,
    pub self_node_index: usize,
    pub round_duration: u64,
    pub skip_waiting_ibd: bool,
}

impl<T: TapyrusApi> NodeParameters<T> {
    pub fn new(
        to_address: Address,
        pubkey_list: Vec<PublicKey>,
        private_key: PrivateKey,
        threshold: u8,
        rpc: T,
        round_duration: u64,
        skip_waiting_ibd: bool,
    ) -> NodeParameters<T> {
        let secp = secp256k1::Secp256k1::new();
        let self_pubkey = private_key.public_key(&secp);
        let signer_id = SignerID {
            pubkey: self_pubkey,
        };

        let mut pubkey_list = pubkey_list;
        &pubkey_list.sort();
        let self_node_index = sender_index(&signer_id, &pubkey_list);
        NodeParameters {
            pubkey_list,
            threshold,
            private_key,
            rpc: Arc::new(rpc),
            address: to_address,
            signer_id,
            self_node_index,
            round_duration,
            skip_waiting_ibd,
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
}
