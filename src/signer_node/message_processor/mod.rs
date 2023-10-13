mod process_blockparticipants;
mod process_blocksig;
mod process_blockvss;
mod process_candidateblock;
mod process_completedblock;
pub use process_blockparticipants::process_blockparticipants;
pub use process_blocksig::process_blocksig;
pub use process_blockvss::process_blockvss;
pub use process_candidateblock::process_candidateblock;
pub use process_completedblock::process_completedblock;

use crate::crypto::multi_party_schnorr::Keys;
use crate::crypto::multi_party_schnorr::{LocalSig, SharedKeys};
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::ConnectionManager;
use crate::net::Message;
use crate::net::MessageType;
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use crate::signer_node::SharedSecret;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeParameters, NodeState};
use tapyrus::blockdata::block::Block;
use tapyrus::hash_types::BlockSigHash;

fn get_valid_block(state: &NodeState, blockhash: BlockSigHash) -> Result<&Block, Error> {
    let block_opt = match state {
        NodeState::Master {
            candidate_block, ..
        } => candidate_block,
        NodeState::Member {
            candidate_block, ..
        } => candidate_block,
        _ => {
            log::error!("Invalid node state: {:?}", state);
            return Err(Error::InvalidNodeState);
        }
    };
    match block_opt {
        None => {
            log::error!("Invalid message received. candidate block is not set.");
            Err(Error::InvalidBlock)
        }
        Some(block) if block.header.signature_hash() != blockhash => {
            log::error!("Invalid message received. Received message is based different block. expected: {:?}, actual: {:?}", block.header.signature_hash(), blockhash);
            Err(Error::InvalidBlock)
        }
        Some(block) => Ok(block),
    }
}

/// Create own VSSs and send to each other signers.
/// Returns
///     * own random key pair
///     * a VSS for itself(for positive and negative)
///     * own commitments
pub fn create_block_vss<T, C>(
    block: Block,
    params: &NodeParameters<T>,
    conman: &C,
    block_height: u32,
) -> (Keys, SharedSecret, SharedSecret)
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let sharing_params = params.sharing_params(block_height);

    let self_node_index = params.self_node_index(block_height);

    let (
        key,
        vss_scheme_for_positive,
        secret_shares_for_positive,
        vss_scheme_for_negative,
        secret_shares_for_negative,
    ) = Vss::create_block_shares(
        self_node_index + 1,
        sharing_params.threshold + 1,
        sharing_params.share_count,
    );

    for i in 0..params.pubkey_list(block_height).len() {
        // Skip broadcasting if it is vss for myself. Just return this.
        if i == self_node_index {
            continue;
        }

        conman.send_message(Message {
            message_type: MessageType::Blockvss(
                block.header.signature_hash(),
                vss_scheme_for_positive.clone(),
                secret_shares_for_positive[i],
                vss_scheme_for_negative.clone(),
                secret_shares_for_negative[i],
            ),
            sender_id: params.signer_id,
            receiver_id: Some(SignerID {
                pubkey: params.pubkey_list(block_height)[i],
            }),
        });
    }

    (
        key,
        SharedSecret {
            vss: vss_scheme_for_positive.clone(),
            secret_share: secret_shares_for_positive[self_node_index],
        },
        SharedSecret {
            vss: vss_scheme_for_negative.clone(),
            secret_share: secret_shares_for_negative[self_node_index],
        },
    )
}

fn generate_local_sig<T>(
    blockhash: BlockSigHash,
    shared_block_secrets: &BidirectionalSharedSecretMap,
    prev_state: &NodeState,
    params: &NodeParameters<T>,
) -> Result<(bool, SharedKeys, LocalSig), Error>
where
    T: TapyrusApi,
{
    log::trace!(
        "number of shared_block_secrets: {:?}",
        shared_block_secrets.len()
    );
    let block = get_valid_block(prev_state, blockhash)?;
    let block_height = prev_state.block_height();
    let federation = params.get_federation_by_block_height(block_height);

    Vss::create_local_sig_from_shares(
        &federation.node_secret_share(),
        params.self_node_index(block_height) + 1,
        shared_block_secrets,
        &block,
    )
}

fn broadcast_localsig<C: ConnectionManager>(
    sighash: BlockSigHash,
    local_sig: &LocalSig,
    conman: &C,
    signer_id: &SignerID,
) {
    conman.broadcast_message(Message {
        message_type: MessageType::Blocksig(
            sighash,
            local_sig.gamma_i.clone(),
            local_sig.e.clone(),
        ),
        sender_id: signer_id.clone(),
        receiver_id: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::tests::helper::node_state_builder::BuilderForTest;
    use tapyrus::consensus::encode::deserialize;
    use tapyrus::hashes::hex::FromHex;

    const BLOCK: &str = "01000000a8b61e31f3d6b655eb8fc387a22d139f141a14cb79c3a12a18192aa4d25941dfcb2edbbd1385a5d5c3bd037b6fd0ca8d691c13875fa74014a115f096a59be33a3447345d02f1420d9f5bc070aa00dc2bcb201ef470842fa5ec4f5c9986345ee91ae23b5e00000101000000010000000000000000000000000000000000000000000000000000000000000000260000000401260101ffffffff0200f2052a010000001976a9145f3f3758e7a4cf159c7bdb441ae4ff80999c62e888ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000";
    const HASH: &str = "a33fa85960e40880139c5d2e2d7f5e98b3674f257d8ea983d0b53e9053db195b";
    const INVALID_HASH: &str = "0000db53903eb5d083a98e7d254f67b3985e7f2d2e5d9c138008e46059a83fa3";

    #[test]
    fn test_get_valid_block_valid_for_master() {
        let block = deserialize::<Block>(&hex::decode(BLOCK).unwrap()).ok();
        let state = Master::for_test().candidate_block(block.clone()).build();
        let blockhash = BlockSigHash::from_hex(HASH).unwrap();
        assert_eq!(*get_valid_block(&state, blockhash).unwrap(), block.unwrap());
    }

    #[test]
    fn test_get_valid_block_valid_for_member() {
        let block = deserialize::<Block>(&hex::decode(BLOCK).unwrap()).ok();
        let state = Member::for_test().candidate_block(block.clone()).build();
        let blockhash = BlockSigHash::from_hex(HASH).unwrap();
        assert_eq!(*get_valid_block(&state, blockhash).unwrap(), block.unwrap());
    }

    #[test]
    fn test_get_valid_block_invalid_node_state() {
        let state = NodeState::Joining;
        let blockhash = BlockSigHash::from_hex(HASH).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }

    #[test]
    fn test_get_valid_block_invalid_blockhash_for_master() {
        let block = deserialize::<Block>(&hex::decode(BLOCK).unwrap()).ok();
        let state = Master::for_test().candidate_block(block.clone()).build();
        let blockhash = BlockSigHash::from_hex(INVALID_HASH).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }

    #[test]
    fn test_get_valid_block_invalid_blockhash_for_member() {
        let block = deserialize::<Block>(&hex::decode(BLOCK).unwrap()).ok();
        let state = Member::for_test().candidate_block(block.clone()).build();
        let blockhash = BlockSigHash::from_hex(INVALID_HASH).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }
}
