use crate::blockdata::hash::SHA256Hash;
use crate::blockdata::Block;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::errors::Error;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::signer_node::message_processor::{
    broadcast_localsig, generate_local_sig, get_valid_block,
};
use crate::signer_node::node_state::builder::{Builder, Master, Member};
use crate::signer_node::NodeParameters;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeState, SharedSecret};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;
use std::collections::HashSet;

pub fn process_blockvss<T, C>(
    sender_id: &SignerID,
    blockhash: SHA256Hash,
    vss_for_positive: VerifiableSS,
    secret_share_for_positive: FE,
    vss_for_negative: VerifiableSS,
    secret_share_for_negative: FE,
    prev_state: &NodeState,
    priv_shared_keys: &SharedKeys,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    // Ignore the message when the sender is myself.
    if *sender_id == params.signer_id {
        return prev_state.clone();
    }

    let new_shared_block_secrets = match store_received_vss(
        sender_id,
        prev_state,
        vss_for_positive,
        secret_share_for_positive,
        vss_for_negative,
        secret_share_for_negative,
    ) {
        Ok(shared_block_secrets) => shared_block_secrets,
        Err(e) => {
            error!("Error: {:?}, state: {:?}", e, prev_state);
            return prev_state.clone();
        }
    };

    let candidate_block = match get_valid_block(prev_state, blockhash) {
        Ok(b) => b,
        Err(e) => {
            error!("Error: {:?}, state: {:?}", e, prev_state);
            return prev_state.clone();
        }
    };

    match prev_state {
        NodeState::Master { participants, .. } => {
            let mut state_builder = Master::from_node_state(prev_state.clone());

            // Broadcast blockparticipants message when the master haven't broadcast yet and met
            // the threshold.
            if participants.len() == 0
                && new_shared_block_secrets.len() >= params.threshold as usize
            {
                let participants = select_participants_for_signing(
                    &new_shared_block_secrets,
                    params.threshold as usize,
                );

                let shared_block_secrets_by_participants = new_shared_block_secrets
                    .clone()
                    .into_iter()
                    .filter(|(i, ..)| participants.contains(i))
                    .collect();

                let (block_shared_keys, local_sig) = match generate_local_sig(
                    candidate_block.sighash(),
                    &shared_block_secrets_by_participants,
                    &params.node_secret_share(),
                    prev_state,
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

                broadcast_blockparticipants(
                    &participants,
                    candidate_block,
                    conman,
                    &params.signer_id,
                );

                broadcast_localsig(
                    candidate_block.sighash(),
                    &local_sig,
                    conman,
                    &params.signer_id,
                );

                state_builder
                    .participants(participants)
                    .block_shared_keys(Some(block_shared_keys))
                    .insert_signature(params.signer_id.clone(), local_sig);
            }

            state_builder
                .shared_block_secrets(new_shared_block_secrets)
                .build()
        }
        NodeState::Member { participants, .. } => {
            let mut state_builder = Member::from_node_state(prev_state.clone());

            // Broadcast blocksig message when a member node receives blockvss after
            // blockparticipants received. Usually nodes receives blockparticipants first, but if
            // nodes got blockvss message first, node needs to broadcast blocksig at this time.
            if participants.contains(&params.signer_id) {
                let (block_shared_keys, local_sig) = match generate_local_sig(
                    candidate_block.sighash(),
                    &new_shared_block_secrets,
                    &params.node_secret_share(),
                    prev_state,
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

                broadcast_localsig(
                    candidate_block.sighash(),
                    &local_sig,
                    conman,
                    &params.signer_id,
                );

                state_builder.block_shared_keys(Some(block_shared_keys));
            }

            state_builder
                .shared_block_secrets(new_shared_block_secrets)
                .build()
        }
        _ => prev_state.clone(),
    }
}

fn broadcast_blockparticipants<C: ConnectionManager>(
    participants: &HashSet<SignerID>,
    block: &Block,
    conman: &C,
    self_signer_id: &SignerID,
) {
    conman.broadcast_message(Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Blockparticipants(
                block.sighash(),
                participants.clone(),
            ),
        ),
        sender_id: self_signer_id.clone(),
        receiver_id: None,
    });
}

/// Select participants for signing
/// The selection rule is who the one's blockvss message was arrived to the master node before met the
/// threshold.
fn select_participants_for_signing(
    shared_block_secrets: &BidirectionalSharedSecretMap,
    threshold: usize,
) -> HashSet<SignerID> {
    shared_block_secrets
        .iter()
        .take(threshold)
        .map(|(signer_id, ..)| signer_id.clone())
        .collect()
}

/// Store received vss
fn store_received_vss(
    sender_id: &SignerID,
    prev_state: &NodeState,
    vss_for_positive: VerifiableSS,
    secret_share_for_positive: FE,
    vss_for_negative: VerifiableSS,
    secret_share_for_negative: FE,
) -> Result<BidirectionalSharedSecretMap, Error> {
    let mut new_shared_block_secrets;
    match prev_state {
        NodeState::Master {
            shared_block_secrets,
            round_is_done: false,
            ..
        } => {
            new_shared_block_secrets = shared_block_secrets.clone();
        }
        NodeState::Member {
            shared_block_secrets,
            ..
        } => {
            new_shared_block_secrets = shared_block_secrets.clone();
        }
        _ => return Err(Error::InvalidNodeState),
    }

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

    Ok(new_shared_block_secrets)
}

#[cfg(test)]
mod tests {
    use super::process_blockvss;
    use crate::blockdata::hash::SHA256Hash;
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
    use curv::{FE, GE};
    use serde_json::Value;
    use std::collections::HashSet;

    #[test]
    fn test_process_blockvss_master_invalid_block() {
        // When the node receives an invalid block,
        // it should skip broadcasting participants message and return prev_state.
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            _,
            _,
            _,
        ) = load_test_case(&contents, "process_blockvss_master_invalid_block", rpc);

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
        conman.assert();
    }

    #[test]
    fn test_process_blockvss_master_with_1_shared_block_secrets() {
        // When
        //     - the node has own secrets
        //     - the node receives a valid block and secrets
        //     - the number of secrets meets threshold,
        // it should
        //     - broadcast blockparticipants message
        //     - update shared_block_secrets
        //     - broadcast blocksig message
        //     - update block_shared_keys
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let mut conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            expected_participants,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockvss_master_with_1_shared_block_secrets",
            rpc,
        );

        conman.should_broadcast(Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Blockparticipants(
                    blockhash,
                    expected_participants.clone(),
                ),
            ),
            sender_id: params.signer_id.clone(),
            receiver_id: None,
        });

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

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        conman.assert();
        match next {
            NodeState::Master {
                block_shared_keys,
                shared_block_secrets,
                ..
            } => {
                assert_eq!(shared_block_secrets.len(), 2);
                assert_eq!(block_shared_keys, expected_block_shared_keys);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
    }

    #[test]
    fn test_process_blockvss_master_with_all_shared_block_secrets_has_participants() {
        // When
        //     - the node receives a valid block and secrets
        //     - and the number of secrets already meets threshold and broadcasted blockparticipants message.
        //     - node state has participants data.
        // it should
        //     - skip broadcasting blockparticipants message
        //     - update shared_block_secrets
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            _,
            _,
            _,
        ) = load_test_case(
            &contents,
            "process_blockvss_master_with_all_shared_block_secrets_has_participants",
            rpc,
        );

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        match next {
            NodeState::Master {
                block_shared_keys,
                shared_block_secrets,
                ..
            } => {
                assert_eq!(shared_block_secrets.len(), 3);
                assert_eq!(block_shared_keys, None);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
        conman.assert();
    }

    #[test]
    fn test_process_blockvss_member_without_block() {
        // When the node
        //    - receives a valid block and secrets
        //    - but has no block hash in prev_state,
        // it should skip storing received block vss.
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            _,
            _,
            _,
        ) = load_test_case(&contents, "process_blockvss_member_without_block", rpc);

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blockvss_member_invalid_block() {
        // When the node receives an invalid block,
        // it should skip storing received block vss.
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            _,
            _,
            _,
        ) = load_test_case(&contents, "process_blockvss_member_invalid_block", rpc);

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blockvss_member_with_1_shared_block_secrets() {
        // When
        //     - the node receives a valid block and secrets
        // it should
        //     - store vss
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            _,
            _,
            _,
        ) = load_test_case(
            &contents,
            "process_blockvss_member_with_1_shared_block_secrets",
            rpc,
        );

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        match next {
            NodeState::Member {
                block_shared_keys,
                shared_block_secrets,
                ..
            } => {
                assert_eq!(shared_block_secrets.len(), 2);
                assert_eq!(block_shared_keys, None);
            }
            _ => {
                panic!("NodeState should be Member");
            }
        }
        conman.assert();
    }

    #[test]
    fn test_process_blockvss_member_had_got_participants_first() {
        // When the node
        //     - is member.
        //     - had already received blockparticipants message before. So it has participants data
        //       in the node state.
        //     - receives a valid block and secrets.
        // it should
        //     - store vss
        //     - broadcast blocksig message.
        let contents = load_test_vector("./tests/resources/process_blockvss.json").unwrap();

        let mut conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_keys,
            prev_state,
            params,
            _,
            expected_localsig,
            expected_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockvss_member_had_got_participants_first",
            rpc,
        );

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

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &priv_shared_keys,
            &conman,
            &params,
        );
        match next {
            NodeState::Member {
                block_shared_keys,
                shared_block_secrets,
                ..
            } => {
                assert_eq!(shared_block_secrets.len(), 2);
                assert_eq!(block_shared_keys, expected_block_shared_keys);
            }
            _ => {
                panic!("NodeState should be Member");
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
        SHA256Hash,
        VerifiableSS,
        FE,
        VerifiableSS,
        FE,
        SharedKeys,
        NodeState,
        NodeParameters<MockRpc>,
        HashSet<SignerID>,
        Option<LocalSig>,
        Option<(bool, FE, GE)>,
    ) {
        let v = &contents["cases"][case];

        let params = to_node_parameters(&v, rpc);

        let block_key: Option<FE> = serde_json::from_value(v["block_key"].clone()).unwrap();
        let block = to_block(&v["candidate_block"]);

        let sender = to_signer_id(&v["received"]["sender"].as_str().unwrap().to_string());
        let hex = hex::decode(v["received"]["block_hash"].as_str().unwrap()).unwrap();
        let blockhash = SHA256Hash::from_slice(&hex[..]).unwrap();
        let vss_for_positive: VerifiableSS =
            serde_json::from_value(v["received"]["vss_for_positive"].clone()).unwrap();
        let secret_share_for_positive = to_fe(&v["received"]["secret_share_for_positive"]);
        let vss_for_negative =
            serde_json::from_value(v["received"]["vss_for_negative"].clone()).unwrap();
        let secret_share_for_negative = to_fe(&v["received"]["secret_share_for_negative"]);

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

        let participants = to_participants(&v["participants"]);

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

        let expected_participants: HashSet<SignerID> = {
            let r: HashSet<String> = serde_json::from_value(v["expected_participants"].clone())
                .unwrap_or(HashSet::new());
            r.iter().map(|i| to_signer_id(i)).collect()
        };

        let expected_localsig = to_local_sig(&v["expected_localsig"]);
        let expected_block_shared_keys = to_block_shared_keys(&v["expected_block_shared_keys"]);

        (
            sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            priv_shared_key,
            prev_state,
            params,
            expected_participants,
            expected_localsig,
            expected_block_shared_keys,
        )
    }
}
