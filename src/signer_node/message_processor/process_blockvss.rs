use crate::blockdata::hash::Hash;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::errors::Error;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::message_processor::get_valid_block;
use crate::signer_node::node_state::builder::{Builder, Master, Member};
use crate::signer_node::{BidirectionalSharedSecretMap, NodeState, SharedSecret};
use crate::signer_node::{NodeParameters, ToSharedSecretMap};
use crate::util::jacobi;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, FE};
use std::borrow::Borrow;
use std::collections::HashSet;

pub fn process_blockvss<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    vss_for_positive: VerifiableSS,
    secret_share_for_positive: FE,
    vss_for_negative: VerifiableSS,
    secret_share_for_negative: FE,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
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
        NodeState::Master { .. } => {
            let mut state_builder = Master::from_node_state(prev_state.clone());

            if new_shared_block_secrets.len() >= params.threshold as usize {
                let participants = select_participants_for_signing(&new_shared_block_secrets);
                broadcast_blockparticipants(
                    &participants,
                    &new_shared_block_secrets,
                    candidate_block,
                    conman,
                    &params.signer_id,
                );
                state_builder.participants(participants);
            }

            state_builder
                .shared_block_secrets(new_shared_block_secrets)
                .build()
        }
        NodeState::Member { .. } => Member::from_node_state(prev_state.clone())
            .shared_block_secrets(new_shared_block_secrets)
            .build(),
        _ => prev_state.clone(),
    }
}

fn broadcast_blockparticipants<C: ConnectionManager>(
    participants: &HashSet<SignerID>,
    shared_block_secrets: &BidirectionalSharedSecretMap,
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
) -> HashSet<SignerID> {
    shared_block_secrets
        .iter()
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
    use crate::blockdata::hash::Hash;
    use crate::crypto::multi_party_schnorr::SharedKeys;
    use crate::net::SignerID;
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::signer_node::*;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_state_builder::BuilderForTest;
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::*;
    use curv::{FE, GE};
    use serde_json::Value;

    #[test]
    fn test_process_blockvss_master_invalid_block() {
        // When the node receives an invalid block,
        // it should skip generating block_shared_keys and return prev_state.
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
            _expect_block_shared_keys,
        ) = load_test_case(&contents, "process_blockvss_master_invalid_block", rpc);

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blockvss_master_with_1_shared_block_secrets() {
        // When
        //     - the node receives a valid block and secrets
        //     - but the number of secrets is not enough to generate block_shaked_keys,
        // it should
        //     - skip generating block_shared_keys
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
            _expect_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockvss_master_with_1_shared_block_secrets",
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
            &conman,
            &params,
        );
        match next {
            NodeState::Master {
                block_shared_keys,
                shared_block_secrets,
                ..
            } => {
                assert_eq!(shared_block_secrets.len(), 2);
                assert_eq!(block_shared_keys, None);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
    }

    #[test]
    fn test_process_blockvss_master_with_all_shared_block_secrets() {
        // When
        //     - the node receives a valid block and secrets
        //     - and the number of secrets is enough to generate block_shaked_keys,
        // it should generate block_shared_keys
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
            expect_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockvss_master_with_all_shared_block_secrets",
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
                assert_eq!(block_shared_keys, expect_block_shared_keys);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
    }

    #[test]
    fn test_process_blockvss_member_without_block() {
        // When the node
        //    - receives a valid block and secrets
        //    - but has no block hash in prev_state,
        // it should skip generating block_shared_keys and return prev_state.
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
            _expect_block_shared_keys,
        ) = load_test_case(&contents, "process_blockvss_member_without_block", rpc);

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blockvss_member_invalid_block() {
        // When the node receives an invalid block,
        // it should skip generating block_shared_keys and return prev_state.
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
            _expect_block_shared_keys,
        ) = load_test_case(&contents, "process_blockvss_member_invalid_block", rpc);

        let next = process_blockvss(
            &sender,
            blockhash,
            vss_for_positive,
            secret_share_for_positive,
            vss_for_negative,
            secret_share_for_negative,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blockvss_member_with_1_shared_block_secrets() {
        // When
        //     - the node receives a valid block and secrets
        //     - but the number of secrets is not enough to generate block_shaked_keys,
        // it should
        //     - skip generating block_shared_keys
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
            _expect_block_shared_keys,
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
    }

    #[test]
    fn test_process_blockvss_member_with_all_shared_block_secrets() {
        // When
        //     - the node receives a valid block and secrets
        //     - and the number of secrets is enough to generate block_shaked_keys,
        // it should generate block_shared_keys
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
            expect_block_shared_keys,
        ) = load_test_case(
            &contents,
            "process_blockvss_member_with_all_shared_block_secrets",
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
            &conman,
            &params,
        );
        match next {
            NodeState::Member {
                block_shared_keys,
                shared_block_secrets,
                ..
            } => {
                assert_eq!(shared_block_secrets.len(), 3);
                assert_eq!(block_shared_keys, expect_block_shared_keys);
            }
            _ => {
                panic!("NodeState should be Member");
            }
        }
    }

    fn load_test_case(
        contents: &Value,
        case: &str,
        rpc: MockRpc,
    ) -> (
        SignerID,
        Hash,
        VerifiableSS,
        FE,
        VerifiableSS,
        FE,
        SharedKeys,
        NodeState,
        NodeParameters<MockRpc>,
        Option<(bool, FE, GE)>,
    ) {
        let v = &contents["cases"][case];

        let params = to_node_parameters(&v, rpc);

        let block_key: Option<FE> = serde_json::from_value(v["block_key"].clone()).unwrap();
        let block = to_block(&v["candidate_block"]);

        let sender = to_signer_id(&v["received"]["sender"].as_str().unwrap().to_string());
        let hex = hex::decode(v["received"]["block_hash"].as_str().unwrap()).unwrap();
        let blockhash = Hash::from_slice(&hex[..]).unwrap();
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

        let prev_state = match v["role"].as_str().unwrap() {
            "master" => Master::for_test()
                .block_key(block_key)
                .candidate_block(block.clone())
                .shared_block_secrets(shared_block_secrets)
                .build(),
            "member" => Member::for_test()
                .block_key(block_key)
                .candidate_block(block.clone())
                .shared_block_secrets(shared_block_secrets)
                .build(),
            _ => panic!("test should be fail"),
        };

        let block_shared_key = if v["block_shared_key"].is_null() {
            None
        } else {
            Some((
                v["block_shared_key"]["positive"].as_bool().unwrap(),
                to_fe(&v["block_shared_key"]["x_i"]),
                to_point(&v["block_shared_key"]["y"]),
            ))
        };
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
            block_shared_key,
        )
    }
}
