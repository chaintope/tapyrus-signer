use crate::blockdata::Block;
use crate::net::{ConnectionManager, SignerID};
use crate::rpc::TapyrusApi;
use crate::signer_node::{NodeState, SignerNode};

pub fn process_completedblock<T, C>(
    sender_id: &SignerID,
    _block: &Block,
    signer_node: &mut SignerNode<T, C>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    if signer_node.is_master(sender_id) {
        signer_node.start_next_round(false)
    } else {
        signer_node.current_state.clone()
    }
}
