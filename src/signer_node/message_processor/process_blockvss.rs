use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::crypto::multi_party_schnorr::SharedKeys;
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

#[cfg(test)]
mod tests {
    use super::process_blockvss;
    use crate::blockdata::hash::Hash;
    use crate::crypto::multi_party_schnorr::SharedKeys;
    use crate::signer_node::*;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::node_state_builder::{Builder, Master, Member};
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;
    use bitcoin::PublicKey;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::*;
    use curv::FE;
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
            &priv_shared_keys,
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
            &priv_shared_keys,
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
            &priv_shared_keys,
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
            &priv_shared_keys,
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
            &priv_shared_keys,
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
            &priv_shared_keys,
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
            &priv_shared_keys,
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

        let private_key = private_key_from_wif(&v["node_private_key"]);
        let public_keys: Vec<PublicKey> = v["public_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pk| to_public_key(pk))
            .collect();
        let threshold = v["threshold"].as_u64().unwrap();
        let sharing_params = ShamirSecretSharing {
            threshold: (threshold - 1) as usize,
            share_count: public_keys.len(),
        };
        let params = NodeParametersBuilder::new()
            .rpc(rpc)
            .threshold(threshold as u8)
            .pubkey_list(public_keys.clone())
            .private_key(private_key)
            .build();

        let block_key = if v["block_key"].is_null() {
            None
        } else {
            Some(to_fe(&v["block_key"]))
        };
        let block = if v["candidate_block"].is_null() {
            None
        } else {
            Some(to_block(&v["candidate_block"]))
        };

        let sender = to_signer_id(&v["received"]["sender"].as_str().unwrap().to_string());
        let hex = hex::decode(v["received"]["block_hash"].as_str().unwrap()).unwrap();
        let blockhash = Hash::from_slice(&hex[..]).unwrap();
        let vss_for_positive = to_vss(&v["received"]["vss_for_positive"], sharing_params.clone());
        let secret_share_for_positive = to_fe(&v["received"]["secret_share_for_positive"]);
        let vss_for_negative = to_vss(&v["received"]["vss_for_negative"], sharing_params.clone());
        let secret_share_for_negative = to_fe(&v["received"]["secret_share_for_negative"]);

        let priv_shared_key = SharedKeys {
            x_i: to_fe(&v["priv_shared_key"]["x_i"]),
            y: to_point(&v["priv_shared_key"]["y"]),
        };

        let shared_block_secrets = v["shared_block_secrets"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, value)| {
                (
                    to_signer_id(k),
                    (
                        to_shared_secret(&value[0], sharing_params.clone()),
                        to_shared_secret(&value[1], sharing_params.clone()),
                    ),
                )
            })
            .collect();

        let prev_state = match v["role"].as_str().unwrap() {
            "master" => Master::new()
                .block_key(block_key)
                .candidate_block(block.unwrap().clone())
                .shared_block_secrets(shared_block_secrets)
                .build(),
            "member" => Member::new()
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
