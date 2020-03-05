use crate::blockdata::hash::Hash;
use crate::crypto::multi_party_schnorr::{LocalSig, Parameters, SharedKeys};
use crate::errors::Error;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::message_processor::get_valid_block;
use crate::signer_node::node_state::builder::{Builder, Master, Member};
use crate::signer_node::ToSharedSecretMap;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeParameters, NodeState};
use crate::util::jacobi;
use curv::elliptic::curves::traits::ECPoint;
use curv::BigInt;
use std::collections::HashSet;
use std::iter::FromIterator;

pub fn process_blockparticipants<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    participants: HashSet<SignerID>,
    priv_shared_keys: &SharedKeys,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    // TODO: Check whether the sender_id is master.
    // TODO: refactor creating generic function for Master and Member node state.

    if !participants.contains(&params.signer_id) {
        // Do nothing if the node is not included in participants.
        return create_next_state(prev_state, participants);
    }

    // Get values from the node state.
    let (shared_block_secrets, block) = match &prev_state {
        NodeState::Master {
            shared_block_secrets: s,
            candidate_block: Some(b),
            ..
        } => (s, b),
        NodeState::Member {
            shared_block_secrets: s,
            candidate_block: Some(b),
            ..
        } => (s, b),
        _ => return prev_state.clone(),
    };

    // Check whether the all VSSs of participants are collected.
    let has: HashSet<SignerID> = shared_block_secrets
        .iter()
        .map(|(signer_id, ..)| signer_id.clone())
        .collect();
    if !participants.is_subset(&has) {
        return create_next_state(prev_state, participants);
    }

    // Generate local signature and broadcast it.
    let block_shared_keys = match broadcast_local_sig(
        blockhash,
        &shared_block_secrets,
        priv_shared_keys,
        prev_state,
        conman,
        params,
    ) {
        Ok((is_positive, shared_keys)) => (is_positive, shared_keys.x_i, shared_keys.y),
        Err(e) => {
            error!("Error: {:?}, state: {:?}", e, prev_state);
            return prev_state.clone();
        }
    };

    create_next_state(prev_state, participants)
}

fn broadcast_local_sig<T, C>(
    blockhash: Hash,
    shared_block_secrets: &BidirectionalSharedSecretMap,
    priv_shared_keys: &SharedKeys,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> Result<(bool, SharedKeys), Error>
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

    return Ok((is_positive, shared_keys));
}

fn create_next_state(prev_state: &NodeState, participants: HashSet<SignerID>) -> NodeState {
    match prev_state {
        NodeState::Master { .. } => Master::from_node_state(prev_state.clone())
            .participants(participants)
            .build(),
        NodeState::Member { .. } => Member::from_node_state(prev_state.clone())
            .participants(participants)
            .build(),
        prev_state @ _ => prev_state.clone(),
    }
}
