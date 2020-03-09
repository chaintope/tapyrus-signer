mod process_blockparticipants;
mod process_blocksig;
mod process_blockvss;
mod process_candidateblock;
mod process_completedblock;
mod process_nodevss;
pub use process_blockparticipants::process_blockparticipants;
pub use process_blocksig::process_blocksig;
pub use process_blockvss::process_blockvss;
pub use process_candidateblock::process_candidateblock;
pub use process_completedblock::process_completedblock;
pub use process_nodevss::process_nodevss;

use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::errors::Error;
use crate::signer_node::{NodeState, BidirectionalSharedSecretMap, NodeParameters};
use crate::crypto::multi_party_schnorr::{SharedKeys, LocalSig};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use curv::BigInt;
use crate::util::jacobi;
use curv::elliptic::curves::traits::ECPoint;
use crate::net::MessageType;
use crate::net::BlockGenerationRoundMessageType;
use crate::net::ConnectionManager;
use crate::net::Message;
use crate::signer_node::ToSharedSecretMap;

fn get_valid_block(state: &NodeState, blockhash: Hash) -> Result<&Block, Error> {
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
        Some(block) if block.sighash() != blockhash => {
            log::error!("Invalid message received. Received message is based different block. expected: {:?}, actual: {:?}", block.sighash(), blockhash);
            Err(Error::InvalidBlock)
        }
        Some(block) => Ok(block),
    }
}

fn broadcast_local_sig<T, C>(
    blockhash: Hash,
    shared_block_secrets: &BidirectionalSharedSecretMap,
    priv_shared_keys: &SharedKeys,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> Result<(bool, SharedKeys, LocalSig), Error>
    where
        T: TapyrusApi,
        C: ConnectionManager,
{
    let sharing_params = params.sharing_params();
    log::trace!(
        "number of shared_block_secrets: {:?}",
        shared_block_secrets.len()
    );
    let block = get_valid_block(prev_state, blockhash)?;
    let shared_keys_for_positive = Sign::verify_vss_and_construct_key(
        &sharing_params,
        &shared_block_secrets.for_positive(),
        &(params.self_node_index + 1),
    )?;

    let result_for_positive =
        Sign::sign(&shared_keys_for_positive, priv_shared_keys, block.sighash());

    let shared_keys_for_negative = Sign::verify_vss_and_construct_key(
        &sharing_params,
        &shared_block_secrets.for_negative(),
        &(params.self_node_index + 1),
    )?;
    let result_for_negative =
        Sign::sign(&shared_keys_for_negative, priv_shared_keys, block.sighash());

    let p = BigInt::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
        .unwrap();
    let is_positive = jacobi(&shared_keys_for_positive.y.y_coor().unwrap(), &p) == 1;
    let (shared_keys, local_sig) = if is_positive {
        (shared_keys_for_positive, result_for_positive)
    } else {
        (shared_keys_for_negative, result_for_negative)
    };

    conman.broadcast_message(Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Blocksig(
                block.sighash(),
                local_sig.gamma_i,
                local_sig.e,
            ),
        ),
        sender_id: params.signer_id,
        receiver_id: None,
    });

    return Ok((is_positive, shared_keys, local_sig));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::tests::helper::node_state_builder::BuilderForTest;

    const BLOCK: &str = "01000000a8b61e31f3d6b655eb8fc387a22d139f141a14cb79c3a12a18192aa4d25941dfcb2edbbd1385a5d5c3bd037b6fd0ca8d691c13875fa74014a115f096a59be33a3447345d02f1420d9f5bc070aa00dc2bcb201ef470842fa5ec4f5c9986345ee91ae23b5e00000101000000010000000000000000000000000000000000000000000000000000000000000000260000000401260101ffffffff0200f2052a010000001976a9145f3f3758e7a4cf159c7bdb441ae4ff80999c62e888ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000";
    const HASH: &str = "5b19db53903eb5d083a98e7d254f67b3985e7f2d2e5d9c138008e46059a83fa3";
    const INVALID_HASH: &str = "0000db53903eb5d083a98e7d254f67b3985e7f2d2e5d9c138008e46059a83fa3";

    #[test]
    fn test_get_valid_block_valid_for_master() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Master::for_test().candidate_block(block.clone()).build();
        let blockhash = Hash::from_slice(&hex::decode(HASH).unwrap()[..]).unwrap();
        assert_eq!(*get_valid_block(&state, blockhash).unwrap(), block.unwrap());
    }

    #[test]
    fn test_get_valid_block_valid_for_member() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Member::for_test().candidate_block(block.clone()).build();
        let blockhash = Hash::from_slice(&hex::decode(HASH).unwrap()[..]).unwrap();
        assert_eq!(*get_valid_block(&state, blockhash).unwrap(), block.unwrap());
    }

    #[test]
    fn test_get_valid_block_invalid_node_state() {
        let state = NodeState::Joining;
        let blockhash = Hash::from_slice(&hex::decode(HASH).unwrap()[..]).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }

    #[test]
    fn test_get_valid_block_invalid_blockhash_for_master() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Master::for_test().candidate_block(block.clone()).build();
        let blockhash = Hash::from_slice(&hex::decode(INVALID_HASH).unwrap()[..]).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }

    #[test]
    fn test_get_valid_block_invalid_blockhash_for_member() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Member::for_test().candidate_block(block.clone()).build();
        let blockhash = Hash::from_slice(&hex::decode(INVALID_HASH).unwrap()[..]).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }
}
