use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeState, SharedSecret};
use crate::signer_node::{NodeParameters, ToSharedSecretMap};
use crate::util::jacobi;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, FE};
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::SharedKeys;

pub fn process_blockvss<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    vss_for_positive: VerifiableSS,
    secret_share_for_positive: FE,
    vss_for_negative: VerifiableSS,
    secret_share_for_negative: FE,
    priv_shared_keys: &SharedKeys,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    match prev_state {
        NodeState::Master {
            block_key,
            shared_block_secrets,
            candidate_block,
            signatures,
            round_is_done: false,
            ..
        } => {
            let mut new_shared_block_secrets = shared_block_secrets.clone();
            new_shared_block_secrets.insert(
                sender_id.clone(),
                (
                    SharedSecret {
                        vss: vss_for_positive.clone(),
                        secret_share: secret_share_for_positive,
                    },
                    SharedSecret {
                        vss: vss_for_negative.clone(),
                        secret_share: secret_share_for_negative,
                    },
                ),
            );
            let shared_keys = process_blockvss_inner(
                blockhash,
                &new_shared_block_secrets,
                priv_shared_keys,
                prev_state,
                conman,
                params,
            );

            match shared_keys {
                Some(keys) => NodeState::Master {
                    block_key: block_key.clone(),
                    shared_block_secrets: new_shared_block_secrets,
                    block_shared_keys: Some((keys.0, keys.1.x_i, keys.1.y)),
                    candidate_block: candidate_block.clone(),
                    signatures: signatures.clone(),
                    round_is_done: false,
                },
                None => NodeState::Master {
                    block_key: block_key.clone(),
                    shared_block_secrets: new_shared_block_secrets,
                    block_shared_keys: None,
                    candidate_block: candidate_block.clone(),
                    signatures: signatures.clone(),
                    round_is_done: false,
                },
            }
        }
        NodeState::Member {
            block_key,
            shared_block_secrets,
            candidate_block,
            master_index,
            ..
        } => {
            let mut new_shared_block_secrets = shared_block_secrets.clone();
            new_shared_block_secrets.insert(
                sender_id.clone(),
                (
                    SharedSecret {
                        vss: vss_for_positive.clone(),
                        secret_share: secret_share_for_positive,
                    },
                    SharedSecret {
                        vss: vss_for_negative.clone(),
                        secret_share: secret_share_for_negative,
                    },
                ),
            );
            let shared_keys = process_blockvss_inner(
                blockhash,
                &new_shared_block_secrets,
                priv_shared_keys,
                prev_state,
                conman,
                params,
            );

            match shared_keys {
                Some(keys) => NodeState::Member {
                    block_key: block_key.clone(),
                    shared_block_secrets: new_shared_block_secrets,
                    block_shared_keys: Some((keys.0, keys.1.x_i, keys.1.y)),
                    candidate_block: candidate_block.clone(),
                    master_index: *master_index,
                },
                None => NodeState::Member {
                    block_key: block_key.clone(),
                    shared_block_secrets: new_shared_block_secrets,
                    block_shared_keys: None,
                    candidate_block: candidate_block.clone(),
                    master_index: *master_index,
                },
            }
        }
        _ => prev_state.clone(),
    }
}

fn process_blockvss_inner<T, C>(
    blockhash: Hash,
    shared_block_secrets: &BidirectionalSharedSecretMap,
    priv_shared_keys: &SharedKeys,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> Option<(bool, SharedKeys)>
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let sharing_params = params.sharing_params();
    log::trace!(
        "number of shared_block_secrets: {:?}",
        shared_block_secrets.len()
    );
    let block_opt: Option<Block> = match prev_state {
        NodeState::Master {
            candidate_block, ..
        } => Some(candidate_block.clone()),
        NodeState::Member {
            candidate_block, ..
        } => candidate_block.clone(),
        _ => None,
    };
    if let Some(block) = block_opt.clone() {
        if block.sighash() != blockhash {
            log::error!("Invalid blockvss message received. Received message is based different block. expected: {:?}, actual: {:?}", block.sighash(), blockhash);
            return None;
        }
    } else {
        // Signer node need to receive candidateblock before receiving VSS.
        log::error!("Invalid blockvss message received. candidateblock was not received in this round yet, but got VSS.");
        return None;
    }
    if shared_block_secrets.len() == params.pubkey_list.len() {
        let shared_keys_for_positive = Sign::verify_vss_and_construct_key(
            &sharing_params,
            &shared_block_secrets.for_positive(),
            &(params.self_node_index + 1),
        )
        .expect("invalid vss");

        let result_for_positive = Sign::sign(
            &shared_keys_for_positive,
            priv_shared_keys,
            block_opt.clone().unwrap().sighash(),
        );

        let shared_keys_for_negative = Sign::verify_vss_and_construct_key(
            &sharing_params,
            &shared_block_secrets.for_negative(),
            &(params.self_node_index + 1),
        )
        .expect("invalid vss");
        let result_for_negative = Sign::sign(
            &shared_keys_for_negative,
            priv_shared_keys,
            block_opt.clone().unwrap().sighash(),
        );

        let p = BigInt::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )
        .unwrap();
        let is_positive = jacobi(&shared_keys_for_positive.y.y_coor().unwrap(), &p) == 1;
        let (shared_keys, result) = if is_positive {
            (shared_keys_for_positive, result_for_positive)
        } else {
            (shared_keys_for_negative, result_for_negative)
        };

        match result {
            Ok(local_sig) => {
                conman.broadcast_message(Message {
                    message_type: MessageType::BlockGenerationRoundMessages(
                        BlockGenerationRoundMessageType::Blocksig(
                            block_opt.clone().unwrap().sighash(),
                            local_sig.gamma_i,
                            local_sig.e,
                        ),
                    ),
                    sender_id: params.signer_id,
                    receiver_id: None,
                });
            }
            _ => (),
        }
        return Some((is_positive, shared_keys));
    } else {
        return None;
    }
}
