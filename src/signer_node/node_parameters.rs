use crate::crypto::multi_party_schnorr::Parameters;
use crate::federation::{Federation, Federations};
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use std::convert::TryInto;
use std::sync::Arc;
use tapyrus::{Address, PublicKey};

pub struct NodeParameters<T: TapyrusApi> {
    pub rpc: std::sync::Arc<T>,
    pub address: Address,
    /// Own Signer ID. Actually it is signer own public key.
    pub signer_id: SignerID,
    pub round_duration: u64,
    pub round_limit: u64,
    pub skip_waiting_ibd: bool,
    federations: Federations,
}

impl<T: TapyrusApi> NodeParameters<T> {
    pub fn new(
        to_address: Address,
        public_key: PublicKey,
        rpc: T,
        round_duration: u64,
        round_limit: u64,
        skip_waiting_ibd: bool,
        federations: Federations,
    ) -> NodeParameters<T> {
        let signer_id = SignerID { pubkey: public_key };

        NodeParameters {
            rpc: Arc::new(rpc),
            address: to_address,
            signer_id,
            round_duration,
            round_limit,
            skip_waiting_ibd,
            federations,
        }
    }

    pub fn get_federation_by_block_height(&self, block_height: u32) -> &Federation {
        self.federations.get_by_block_height(block_height)
    }

    pub fn get_signer_id_by_index(&self, block_height: u32, index: usize) -> SignerID {
        SignerID {
            pubkey: self.pubkey_list(block_height)[index].clone(),
        }
    }

    pub fn sharing_params(&self, block_height: u32) -> Parameters {
        let t = (self.threshold(block_height) - 1 as u8).try_into().unwrap();
        let n: usize = (self.pubkey_list(block_height).len() as u8)
            .try_into()
            .unwrap();
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

    pub fn threshold(&self, block_height: u32) -> u8 {
        let federation = self.get_federation_by_block_height(block_height);
        federation
            .threshold()
            .expect("threshold should not be None")
    }

    pub fn self_node_index(&self, block_height: u32) -> usize {
        let federation = self.get_federation_by_block_height(block_height);
        federation.node_index()
    }

    pub fn pubkey_list(&self, block_height: u32) -> Vec<PublicKey> {
        let federation = self.get_federation_by_block_height(block_height);
        federation.signers().iter().map(|s| s.pubkey).collect()
    }

    pub fn aggregated_public_key(&self, block_height: u32) -> PublicKey {
        let federation = self.get_federation_by_block_height(block_height);
        federation.aggregated_public_key().unwrap()
    }

    pub fn get_federation_change_for_block_height(&self, block_height: u32) -> Option<&Federation> {
        self.federations
            .get_federation_change_for_block_height(block_height)
    }
}

#[cfg(test)]
mod tests {
    use crate::signer_node::NodeParameters;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::rpc::MockRpc;
    use tapyrus::PublicKey;

    #[test]
    fn test_sort_publickey() {
        let mut pubkeys: Vec<PublicKey> = TEST_KEYS.unsorted_pubkeys();
        NodeParameters::<MockRpc>::sort_publickey(&mut pubkeys);
        assert_eq!(pubkeys, TEST_KEYS.pubkeys());
    }
}
