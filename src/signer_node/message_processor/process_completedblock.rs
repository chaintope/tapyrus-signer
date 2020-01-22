use crate::blockdata::Block;
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use crate::signer_node::{is_master, master_index, next_master_index, NodeParameters, NodeState};

pub fn process_completedblock<T>(
    sender_id: &SignerID,
    _block: &Block,
    prev_state: &NodeState,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
{
    if !is_master(sender_id, prev_state, params) {
        log::warn!("Peer {} may be vicious node. It might swindle as master or your node is behind from others.", sender_id);
        return prev_state.clone(); // Ignore message
    }

    NodeState::RoundComplete {
        master_index: master_index(prev_state, params)
            .expect("Previous state getting round complete should have round master"),
        next_master_index: next_master_index(prev_state, params),
    }
}
