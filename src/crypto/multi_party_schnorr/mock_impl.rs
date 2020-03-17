use crate::crypto::multi_party_schnorr::traits::key_generation_protocol::{
    KeyGenerationProtocol, NodeShare, NodeVSS,
};
use crate::crypto::multi_party_schnorr::traits::signature_issuing_protocol::{
    BlockShare, BlockVSS, LocalSig, SignatureIssuingProtocol,
};
use crate::crypto::multi_party_schnorr::traits::{Error, Secret, Signature};
use secp256k1::rand::prelude::ThreadRng;
use secp256k1::rand::thread_rng;
use secp256k1::{PublicKey, SecretKey};
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::str::FromStr;

struct MockImpl;

fn random_pubkey() -> PublicKey {
    let secp = secp256k1::Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::new(&mut thread_rng()))
}

fn random_secret() -> Secret {
    Secret::from(SecretKey::new(&mut thread_rng()))
}

impl KeyGenerationProtocol for MockImpl {
    fn create_node_vss(
        node_private_key: &SecretKey,
        signer_keys: &Vec<PublicKey>,
        threshold: usize,
    ) -> HashSet<NodeVSS, RandomState> {
        let vss = NodeVSS {
            sender_pubkey: random_pubkey(),
            receiver_pubkey: random_pubkey(),
            commitments: vec![],
            secret: random_secret(),
        };
        let mut set = HashSet::new();
        set.insert(vss);
        set
    }

    fn verify_node_vss(vss: &NodeVSS) -> Result<(), Error> {
        Ok(())
    }

    fn aggregate_node_vss(vss_set: &HashSet<NodeVSS, RandomState>) -> NodeShare {
        NodeShare {
            aggregated_pubkey: random_pubkey(),
            secret_share: random_secret(),
        }
    }
}

impl SignatureIssuingProtocol for MockImpl {
    fn create_block_vss(
        signer_keys: &Vec<PublicKey>,
        threshold: usize,
    ) -> HashSet<BlockVSS, RandomState> {
        let vss = BlockVSS {
            sender_pubkey: random_pubkey(),
            receiver_pubkey: random_pubkey(),
            positive_commitments: vec![],
            positive_secret: random_secret(),
            negative_commitments: vec![],
            negative_secret: random_secret(),
        };
        let mut set = HashSet::new();
        set.insert(vss);
        set
    }

    fn verify_block_vss(vss: &BlockVSS) -> Result<(), Error> {
        Ok(())
    }

    fn aggregate_block_vss(vss_set: &HashSet<BlockVSS, RandomState>) -> BlockShare {
        BlockShare {
            aggregated_pubkey: random_pubkey(),
            positive_secret_share: random_secret(),
            negative_secret_share: random_secret(),
        }
    }

    fn create_local_sig(
        message: &[u8; 32],
        node_share: &NodeShare,
        block_share: &BlockShare,
    ) -> LocalSig {
        LocalSig {
            signer_pubkey: random_pubkey(),
            gamma_i: random_secret(),
        }
    }

    fn verify_local_sig(
        local_sig: &LocalSig,
        node_vss_set: &HashSet<NodeVSS, RandomState>,
        block_vss_set: &HashSet<BlockVSS, RandomState>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn compute_final_signature(
        local_sigs: &HashSet<LocalSig, RandomState>,
        threshold: usize,
    ) -> Result<Signature, Error> {
        Ok(Signature {
            r_x: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            sigma: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::multi_party_schnorr::mock_impl::MockImpl;
    use crate::crypto::multi_party_schnorr::traits::key_generation_protocol::KeyGenerationProtocol;
    use crate::crypto::multi_party_schnorr::traits::signature_issuing_protocol::SignatureIssuingProtocol;
    use crate::tests::helper::keys::TEST_KEYS;
    use secp256k1::PublicKey;
    use std::collections::HashSet;

    #[test]
    fn test() {
        let signer_keys = TEST_KEYS
            .pubkeys()
            .into_iter()
            .map(|i| i.key)
            .collect::<Vec<PublicKey>>();
        let node_vss_set = MockImpl::create_node_vss(&TEST_KEYS.key[0].key, &signer_keys, 3);
        for vss in node_vss_set.iter() {
            MockImpl::verify_node_vss(vss);
        }
        let node_share = MockImpl::aggregate_node_vss(&node_vss_set);

        let block_vss_set = MockImpl::create_block_vss(&signer_keys, 3);
        for vss in block_vss_set.iter() {
            MockImpl::verify_block_vss(vss);
        }
        let block_share = MockImpl::aggregate_block_vss(&block_vss_set);
        let message = [0u8; 32];
        let local_sig = MockImpl::create_local_sig(&message, &node_share, &block_share);
        MockImpl::verify_local_sig(&local_sig, &node_vss_set, &block_vss_set);
        let mut local_sigs = HashSet::new();
        local_sigs.insert(local_sig);
        MockImpl::compute_final_signature(&local_sigs, 3);
    }
}
