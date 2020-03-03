use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::crypto::multi_party_schnorr::{LocalSig, SharedKeys};
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::message_processor::get_valid_block;
use crate::signer_node::utils::sender_index;
use crate::signer_node::NodeState;
use crate::signer_node::ToVerifiableSS;
use crate::signer_node::{NodeParameters, SharedSecretMap, ToSharedSecretMap};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::FE;

pub fn process_blocksig<T, C>(
    sender_id: &SignerID,
    blockhash: Hash,
    gamma_i: FE,
    e: FE,
    priv_shared_keys: &SharedKeys,
    shared_secrets: &SharedSecretMap,
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
            block_shared_keys,
            shared_block_secrets,
            candidate_block,
            signatures,
            round_is_done: false,
        } => {
            let mut new_signatures = signatures.clone();
            new_signatures.insert(sender_id.clone(), (gamma_i, e));
            log::trace!(
                "number of signatures: {:?} (threshold: {:?})",
                new_signatures.len(),
                params.threshold
            );
            let block = match get_valid_block(prev_state, blockhash) {
                Ok(block) => block,
                Err(_) => {
                    return prev_state.clone();
                }
            };

            if new_signatures.len() >= params.threshold as usize {
                if block_shared_keys.is_none() {
                    log::error!("key is not shared.");
                    return prev_state.clone();
                }

                let parties = new_signatures
                    .keys()
                    .map(|k| sender_index(k, &params.pubkey_list))
                    .collect::<Vec<usize>>();
                let key_gen_vss_vec: Vec<VerifiableSS> = shared_secrets.to_vss();
                let local_sigs: Vec<LocalSig> = new_signatures
                    .values()
                    .map(|s| LocalSig {
                        gamma_i: s.0,
                        e: s.1,
                    })
                    .collect();
                let eph_vss_vec: Vec<VerifiableSS> = if block_shared_keys.unwrap().0 {
                    shared_block_secrets.for_positive().to_vss()
                } else {
                    shared_block_secrets.for_negative().to_vss()
                };
                let sum_of_local_sigs = LocalSig::verify_local_sigs(
                    &local_sigs,
                    &parties[..],
                    &key_gen_vss_vec,
                    &eph_vss_vec,
                );

                let verification = match sum_of_local_sigs {
                    Ok(vss_sum) => {
                        let signature = Sign::aggregate(
                            &vss_sum,
                            &local_sigs,
                            &parties[..],
                            block_shared_keys.unwrap().2,
                        );
                        let public_key = priv_shared_keys.y;
                        let hash = block.sighash().into_inner();
                        match signature.verify(&hash, &public_key) {
                            Ok(_) => Ok(signature),
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => {
                        log::error!("local signature is invalid.");
                        return prev_state.clone();
                    }
                };
                let result = match verification {
                    Ok(signature) => {
                        let sig_hex = Sign::format_signature(&signature);
                        let new_block: Block = block.add_proof(hex::decode(sig_hex).unwrap());
                        match params.rpc.submitblock(&new_block) {
                            Ok(_) => Ok(new_block),
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => {
                        log::error!("aggregated signature is invalid");
                        return prev_state.clone();
                    }
                };
                match result {
                    Ok(new_block) => {
                        log::info!(
                                "Round Success. caindateblock(block hash for sign)={:?} completedblock={:?}",
                                block.sighash(),
                                new_block.hash()
                            );
                        // send completeblock message
                        log::info!("Broadcast CompletedBlock message. {:?}", new_block.hash());
                        let message = Message {
                            message_type: MessageType::BlockGenerationRoundMessages(
                                BlockGenerationRoundMessageType::Completedblock(new_block),
                            ),
                            sender_id: params.signer_id.clone(),
                            receiver_id: None,
                        };
                        conman.broadcast_message(message);

                        return NodeState::Master {
                            block_key: block_key.clone(),
                            block_shared_keys: block_shared_keys.clone(),
                            shared_block_secrets: shared_block_secrets.clone(),
                            candidate_block: candidate_block.clone(),
                            signatures: new_signatures,
                            round_is_done: true,
                        };
                    }
                    Err(e) => {
                        log::error!("block rejected by Tapyrus Core: {:?}", e);
                    }
                }
            }
            NodeState::Master {
                block_key: block_key.clone(),
                block_shared_keys: block_shared_keys.clone(),
                shared_block_secrets: shared_block_secrets.clone(),
                candidate_block: candidate_block.clone(),
                signatures: new_signatures,
                round_is_done: false,
            }
        }
        state @ _ => state.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::process_blocksig;
    use crate::blockdata::hash::Hash;
    use crate::crypto::multi_party_schnorr::SharedKeys;
    use crate::signer_node::*;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_state_builder::BuilderForTest;
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;
    use curv::FE;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::iter::FromIterator;
    use crate::signer_node::node_state::builder::{Member, Builder, Master};
    use crate::net::SignerID;

    #[test]
    fn test_process_blocksig_for_member() {
        // if node state is Member, process_blocksig should return Member state(it is same as prev_state).
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, _, params) =
            load_test_case(&contents, "process_blocksig_for_member", rpc);

        let prev_state = Member::for_test().master_index(0).build();
        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_invalid_block() {
        // if node receives invalid block (that means block is not the same as candidate block),
        // node should return prev_state immediately.
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, prev_state, params) =
            load_test_case(&contents, "process_process_blocksig_invalid_block", rpc);

        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_1_valid_block() {
        // when node
        //  - receives a valid block,
        //  - but the number of signatures(1) is not enough (2) to generate a aggregated signature,
        // node should return new Master state which has signatures.

        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, prev_state, params) =
            load_test_case(&contents, "process_blocksig_1_valid_block", rpc);

        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        match prev_state {
            NodeState::Master { signatures, .. } => {
                assert_eq!(signatures.len(), 0);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
        match next {
            NodeState::Master {
                signatures,
                round_is_done,
                ..
            } => {
                assert_eq!(signatures.len(), 1);
                assert_eq!(round_is_done, false);
            }
            _ => {
                panic!("NodeState should be Master");
            }
        }
    }

    #[test]
    fn test_process_blocksig_with_no_block_shared_key() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - but block shared key is not supplied.
        // node should return prev_state.

        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, prev_state, params) =
            load_test_case(&contents, "process_blocksig_with_no_block_shared_key", rpc);

        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_receiving_invaid_signature() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - but received gamma_i and e is invalid.
        // node should return prev_state.

        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, prev_state, params) =
            load_test_case(
                &contents,
                "process_blocksig_receiving_invaid_signature",
                rpc,
            );

        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_with_invaid_signature() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - and received gamma_i and e is valid.
        //  - but node already received invalid signature from other node
        // node should return prev_state.

        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, prev_state, params) =
            load_test_case(&contents, "process_blocksig_with_invaid_signature", rpc);

        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, prev_state);
    }

    #[test]
    fn test_process_blocksig_successfully() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - has block key,
        // then node should
        //  - call rpc submitblock
        //  - send message `Completedblock`
        //  - return Master

        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();

        let conman = TestConnectionManager::new();
        let mut rpc = MockRpc::new();
        rpc.should_call_submitblock(Ok(()));

        let (sender, blockhash, gamma_i, e, priv_shared_key, shared_secrets, prev_state, params) =
            load_test_case(&contents, "process_blocksig_successfully", rpc);

        let next = process_blocksig(
            &sender,
            blockhash,
            gamma_i,
            e,
            &priv_shared_key,
            &shared_secrets,
            &prev_state,
            &conman,
            &params,
        );
        match next {
            NodeState::Master {
                signatures,
                round_is_done,
                ..
            } => {
                params.rpc.assert();
                assert_eq!(signatures.len(), 2);
                assert_eq!(round_is_done, true);
            }
            _ => {
                panic!("NodeState should be Master");
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
        FE,
        FE,
        SharedKeys,
        SharedSecretMap,
        NodeState,
        NodeParameters<MockRpc>,
    ) {
        let v = &contents["cases"][case];

        let params = to_node_parameters(&v, rpc);
        let block_key: Option<FE> = serde_json::from_value(v["block_key"].clone()).unwrap();
        let block = to_block(&v["candidate_block"]);
        let sender = to_signer_id(&v["received"]["sender"].as_str().unwrap().to_string());
        let hex = hex::decode(v["received"]["block_hash"].as_str().unwrap()).unwrap();
        let blockhash = Hash::from_slice(&hex[..]).unwrap();
        let gamma_i = to_fe(&v["received"]["gamma_i"]);
        let e = to_fe(&v["received"]["e"]);

        let priv_shared_key: SharedKeys =
            serde_json::from_value(v["priv_shared_key"].clone()).unwrap();

        let shared_secrets: SharedSecretMap = BTreeMap::from_iter(
            v["shared_secrets"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, value)| (to_signer_id(k), to_shared_secret(&value))),
        );

        let block_shared_keys = if v["block_shared_keys"].is_null() {
            None
        } else {
            Some((
                v["block_shared_keys"]["positive"].as_bool().unwrap(),
                to_fe(&v["block_shared_keys"]["x_i"]),
                to_point(&v["block_shared_keys"]["y"]),
            ))
        };

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
        let signatures = BTreeMap::from_iter(v["signatures"].as_object().unwrap().iter().map(
            |(k, value)| {
                (
                    to_signer_id(k),
                    (to_fe(&value["gamma_i"]), to_fe(&value["e"])),
                )
            },
        ));

        let prev_state = Master::for_test()
            .block_key(block_key)
            .candidate_block(block.clone())
            .block_shared_keys(block_shared_keys)
            .shared_block_secrets(shared_block_secrets)
            .signatures(signatures)
            .build();
        (
            sender,
            blockhash,
            gamma_i,
            e,
            priv_shared_key,
            shared_secrets,
            prev_state,
            params,
        )
    }
}
