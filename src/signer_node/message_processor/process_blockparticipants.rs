use crate::net::{SignerID, ConnectionManager};
use crate::blockdata::hash::Hash;
use crate::signer_node::{NodeState, NodeParameters};
use crate::rpc::TapyrusApi;

pub fn process_blockparticipants<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    participants: Vec<SignerID>,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
    where
        T: TapyrusApi,
        C: ConnectionManager,
{
    unimplemented!();
}