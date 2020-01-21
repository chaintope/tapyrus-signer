use crate::blockdata::Block;
use crate::net::{ConnectionManager, SignerID};
use crate::rpc::TapyrusApi;
use crate::signer_node::utils::sender_index;
use crate::signer_node::{NodeState, SignerNode};

pub fn process_candidateblock<T, C>(
    sender_id: &SignerID,
    block: &Block,
    signer_node: &mut SignerNode<T, C>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    log::info!(
        "candidateblock received. block hash for signing: {:?}",
        block.sighash()
    );

    match &signer_node.current_state {
        NodeState::Member {
            shared_block_secrets,
            block_shared_keys,
            master_index,
            ..
        } => {
            match signer_node.params.rpc.testproposedblock(&block) {
                Ok(_) => {
                    let key = signer_node.create_block_vss(block.clone());
                    // TODO: Errorを処理する必要あるかな？
                    NodeState::Member {
                        block_key: Some(key.u_i),
                        shared_block_secrets: shared_block_secrets.clone(),
                        block_shared_keys: block_shared_keys.clone(),
                        candidate_block: Some(block.clone()),
                        master_index: sender_index(sender_id, &signer_node.params.pubkey_list),
                    }
                }
                Err(_e) => {
                    log::warn!("Received Invalid candidate block sender: {}", sender_id);
                    NodeState::Member {
                        block_key: None,
                        shared_block_secrets: shared_block_secrets.clone(),
                        block_shared_keys: block_shared_keys.clone(),
                        candidate_block: Some(block.clone()),
                        master_index: *master_index,
                    }
                }
            }
        }
        NodeState::Master {
            block_shared_keys,
            shared_block_secrets,
            signatures,
            round_is_done: false,
            ..
        } => {
            let key = signer_node.create_block_vss(block.clone());
            NodeState::Master {
                block_key: Some(key.u_i),
                block_shared_keys: block_shared_keys.clone(),
                shared_block_secrets: shared_block_secrets.clone(),
                candidate_block: block.clone(),
                signatures: signatures.clone(),
                round_is_done: false,
            }
        }
        _ => signer_node.current_state.clone(),
    }
}
