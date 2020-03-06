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
use crate::signer_node::{master_index, ToSharedSecretMap};
use crate::signer_node::{BidirectionalSharedSecretMap, NodeParameters, NodeState};
use crate::util::jacobi;
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, FE, GE};
use serde::Serialize;
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
    // Get values from the node state.
    let (shared_block_secrets, block, master_id) = match &prev_state {
        NodeState::Master {
            shared_block_secrets: s,
            candidate_block: Some(b),
            ..
        } => (s, b, params.signer_id.clone()),
        NodeState::Member {
            shared_block_secrets: s,
            candidate_block: Some(b),
            master_index,
            ..
        } => (s, b, params.get_signer_id_by_index(master_index.clone())),
        _ => return prev_state.clone(),
    };

    if master_id != *sender_id {
        return prev_state.clone();
    }

    if !participants.contains(&params.signer_id) {
        // Do nothing if the node is not included in participants.
        return create_next_state(sender_id, prev_state, participants, None, None);
    }

    // Check whether the all VSSs of participants are collected.
    let has: HashSet<SignerID> = shared_block_secrets
        .iter()
        .map(|(signer_id, ..)| signer_id.clone())
        .collect();
    if !participants.is_subset(&has) {
        return create_next_state(sender_id, prev_state, participants, None, None);
    }

    // Generate local signature and broadcast it.
    let (block_shared_keys, local_sig) = match broadcast_local_sig(
        blockhash,
        &shared_block_secrets,
        priv_shared_keys,
        prev_state,
        conman,
        params,
    ) {
        Ok((is_positive, shared_keys, local_sig)) => {
            ((is_positive, shared_keys.x_i, shared_keys.y), local_sig)
        }
        Err(e) => {
            error!("Error: {:?}, state: {:?}", e, prev_state);
            return prev_state.clone();
        }
    };
    create_next_state(
        sender_id,
        prev_state,
        participants,
        Some(local_sig),
        Some(block_shared_keys),
    )
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

fn create_next_state(
    sender_id: &SignerID,
    prev_state: &NodeState,
    participants: HashSet<SignerID>,
    local_sig: Option<LocalSig>,
    block_shared_keys: Option<(bool, FE, GE)>,
) -> NodeState {
    match prev_state {
        NodeState::Master { .. } => {
            let mut builder = Master::from_node_state(prev_state.clone());
            builder
                .participants(participants)
                .block_shared_keys(block_shared_keys);

            if let Some(local_sig) = local_sig {
                let signatures = builder.borrow_mut_signatures();
                signatures.insert(sender_id.clone(), (local_sig.gamma_i, local_sig.e));
            }

            builder.build()
        }
        NodeState::Member { .. } => Member::from_node_state(prev_state.clone())
            .participants(participants)
            .block_shared_keys(block_shared_keys)
            .build(),
        prev_state @ _ => prev_state.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::process_blockparticipants;
    use crate::blockdata::hash::Hash;
    use crate::crypto::multi_party_schnorr::{LocalSig, SharedKeys};
    use crate::net::SignerID;
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::signer_node::*;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_state_builder::BuilderForTest;
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::*;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::{BigInt, FE, GE};
    use serde_json::Value;
    use std::collections::HashSet;

    #[test]
    fn test_process_blockparticipants_master() {
        // When the node receives valid message.
        // It should
        //     - Broadcast blocksig messsage.
        //     - Store participants
        //     - Store block_shared_keys
        let contents =
            load_test_vector("./tests/resources/process_blockparticipants.json").unwrap();

        let mut conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(&contents, "process_blockparticipants_master", rpc);

        // Add 0 for to make purpose field of gamma_i to 'add'.
        let zero: FE = ECScalar::zero();
        let expected_localsig = expected_localsig.unwrap();
        let gamma_i: FE = expected_localsig.gamma_i + zero;

        conman.should_broadcast(Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Blocksig(blockhash, gamma_i, expected_localsig.e),
            ),
            sender_id: params.signer_id.clone(),
            receiver_id: None,
        });

        let next = process_blockparticipants(
            &sender,
            blockhash,
            participants.clone(),
            &priv_shared_key,
            &prev_state,
            &conman,
            &params,
        );

        match next {
            NodeState::Master {
                block_shared_keys,
                signatures,
                participants: target_participants,
                round_is_done: false,
                ..
            } => {
                assert_eq!(target_participants, participants);
                assert_eq!(signatures.len(), 1);
                assert_eq!(block_shared_keys, expected_block_shared_keys)
            }
            _ => {
                panic!("NodeState is not expected");
            }
        }

        conman.assert();
    }

    #[test]
    fn test_process_blockparticipants_member() {
        // When the node
        //     - receives valid message.
        //     - role is member.
        // It should
        //     - Broadcast blocksig messsage.
        //     - Store participants
        //     - Store block_shared_keys
        let contents =
            load_test_vector("./tests/resources/process_blockparticipants.json").unwrap();

        let mut conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(&contents, "process_blockparticipants_master", rpc);

        // Add 0 for to make purpose field of gamma_i to 'add'.
        let zero: FE = ECScalar::zero();
        let expected_localsig = expected_localsig.unwrap();
        let gamma_i: FE = expected_localsig.gamma_i + zero;

        conman.should_broadcast(Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Blocksig(blockhash, gamma_i, expected_localsig.e),
            ),
            sender_id: params.signer_id.clone(),
            receiver_id: None,
        });

        let next = process_blockparticipants(
            &sender,
            blockhash,
            participants.clone(),
            &priv_shared_key,
            &prev_state,
            &conman,
            &params,
        );

        match next {
            NodeState::Master {
                block_shared_keys,
                signatures,
                participants: target_participants,
                round_is_done: false,
                ..
            } => {
                assert_eq!(target_participants, participants);
                assert_eq!(signatures.len(), 1);
                assert_eq!(block_shared_keys, expected_block_shared_keys)
            }
            _ => {
                panic!("NodeState is not expected");
            }
        }

        conman.assert();
    }

    #[test]
    fn test_process_blockparticipants_not_include_the_node() {
        // When the node
        //     - receives valid message.
        //     - but the participants don't include signer id of the node.
        // It should
        //     - store participants into next state.
        //     - never broadcast blocksig message.
        let contents =
            load_test_vector("./tests/resources/process_blockparticipants.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockparticipants_not_include_the_node",
            rpc,
        );

        let next = process_blockparticipants(
            &sender,
            blockhash,
            participants.clone(),
            &priv_shared_key,
            &prev_state,
            &conman,
            &params,
        );

        match next {
            NodeState::Member {
                block_shared_keys,
                participants: target_participants,
                ..
            } => {
                assert_eq!(target_participants, participants);
                assert_eq!(block_shared_keys, None)
            }
            _ => {
                panic!("NodeState is not expected");
            }
        }

        conman.assert();
    }

    #[test]
    fn test_process_blockparticipants_master_from_fake_master() {
        // When the node
        //     - is master.
        //     - sender_id is not same with master node of the round.
        // It should
        //     - not change state.
        //     - never broadcast blocksig message.
        let contents =
            load_test_vector("./tests/resources/process_blockparticipants.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockparticipants_master_from_fake_master",
            rpc,
        );

        let next = process_blockparticipants(
            &sender,
            blockhash,
            participants.clone(),
            &priv_shared_key,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
        conman.assert();
    }

    #[test]
    fn test_process_blockparticipants_member_from_fake_master() {
        // When the node
        //     - is member.
        //     - sender_id is not same with master node of the round.
        // It should
        //     - not change state.
        //     - never broadcast blocksig message.
        let contents =
            load_test_vector("./tests/resources/process_blockparticipants.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockparticipants_member_from_fake_master",
            rpc,
        );

        let next = process_blockparticipants(
            &sender,
            blockhash,
            participants.clone(),
            &priv_shared_key,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
        conman.assert();
    }

    #[test]
    fn test_process_blockparticipants_with_shortage_shared_block_secrets() {
        // When the node
        //     - receives valid message
        //     - has shortage shared_block_secrets from the threshold.
        // It should
        //     - store participants.
        //     - never broadcast blocksig message.
        // At this case, there is a possibility that the blockparticipants message reached before
        // enough blockvss message. So, store participants here and then make the node possible to
        // progress when the node have collected enough blockvss.
        let contents =
            load_test_vector("./tests/resources/process_blockparticipants.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockparticipants_with_shortage_shared_block_secrets",
            rpc,
        );

        let next = process_blockparticipants(
            &sender,
            blockhash,
            participants.clone(),
            &priv_shared_key,
            &prev_state,
            &conman,
            &params,
        );

        match next {
            NodeState::Member {
                block_shared_keys,
                participants: target_participants,
                ..
            } => {
                assert_eq!(target_participants, participants);
                assert_eq!(block_shared_keys, None)
            }
            _ => {
                panic!("NodeState is not expected");
            }
        }

        conman.assert();
    }

    fn load_test_case(
        contents: &Value,
        case: &str,
        rpc: MockRpc,
    ) -> (
        SignerID,
        Hash,
        HashSet<SignerID>,
        SharedKeys,
        NodeState,
        NodeParameters<MockRpc>,
        Option<LocalSig>,
        Option<(bool, FE, GE)>,
    ) {
        let v = &contents["cases"][case];

        let params = to_node_parameters(&v, rpc);

        let block_key: Option<FE> = serde_json::from_value(v["block_key"].clone()).unwrap();
        let block = to_block(&v["candidate_block"]);

        let sender = to_signer_id(&v["received"]["sender"].as_str().unwrap().to_string());
        let hex = hex::decode(v["received"]["block_hash"].as_str().unwrap()).unwrap();
        let received_participants: HashSet<SignerID> = {
            let r: HashSet<String> = serde_json::from_value(v["received"]["participants"].clone())
                .unwrap_or(HashSet::new());
            r.iter().map(|i| to_signer_id(i)).collect()
        };

        let blockhash = Hash::from_slice(&hex[..]).unwrap();
        let participants: HashSet<SignerID> = {
            let r: HashSet<String> =
                serde_json::from_value(v["participants"].clone()).unwrap_or(HashSet::new());
            r.iter().map(|i| to_signer_id(i)).collect()
        };
        let priv_shared_key: SharedKeys =
            serde_json::from_value(v["priv_shared_key"].clone()).unwrap();
        let shared_block_secrets = v["shared_block_secrets"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, value)| {
                (
                    to_signer_id(k),
                    (to_shared_secret(&value[0]), to_shared_secret(&value[1])),
                )
            })
            .collect();
        let prev_state = match v["role"].as_str().unwrap() {
            "master" => Master::for_test()
                .block_key(block_key)
                .candidate_block(block.clone())
                .shared_block_secrets(shared_block_secrets)
                .participants(participants)
                .build(),
            "member" => Member::for_test()
                .block_key(block_key)
                .candidate_block(block.clone())
                .shared_block_secrets(shared_block_secrets)
                .participants(participants)
                .build(),
            _ => panic!("test should be fail"),
        };

        let expected_localsig = to_local_sig(&v["expected_localsig"]);
        let expected_block_shared_keys = to_block_shared_keys(&v["expected_block_shared_keys"]);

        (
            sender,
            blockhash,
            received_participants,
            priv_shared_key,
            prev_state,
            params,
            expected_localsig,
            expected_block_shared_keys,
        )
    }
}
