use crate::blockdata::hash::Hash;
use crate::blockdata::Block;
use crate::crypto::multi_party_schnorr::{LocalSig, SharedKeys, Signature};
use crate::errors::Error;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::message_processor::get_valid_block;
use crate::signer_node::node_state::builder::{Builder, Master};
use crate::signer_node::utils::sender_index;
use crate::signer_node::ToVerifiableSS;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeState};
use crate::signer_node::{NodeParameters, SharedSecretMap, ToSharedSecretMap};
use bitcoin::PublicKey;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{FE, GE};
use std::collections::BTreeMap;

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
    let (block_shared_keys, shared_block_secrets, signatures) = match prev_state {
        NodeState::Master {
            block_shared_keys,
            shared_block_secrets,
            signatures,
            round_is_done: false,
            ..
        } => (block_shared_keys, shared_block_secrets, signatures),
        _ => {
            // Ignore blocksig message except Master state which is not done.
            return prev_state.clone();
        }
    };

    let mut state_builder = Master::from_node_state(prev_state.clone());

    let new_signatures = store_received_local_sig(sender_id, signatures, gamma_i, e);
    state_builder.signatures(new_signatures.clone());

    log::trace!(
        "number of signatures: {:?} (threshold: {:?})",
        new_signatures.len(),
        params.threshold
    );

    let candidate_block = match get_valid_block(prev_state, blockhash) {
        Ok(block) => block,
        Err(_) => {
            return prev_state.clone();
        }
    };

    // Check whether the number of signatures met the threshold
    if new_signatures.len() < params.threshold as usize {
        return state_builder.build();
    }

    if block_shared_keys.is_none() {
        log::error!("key is not shared.");
        return prev_state.clone();
    }

    let signature = match aggregate_and_verify_signature(
        candidate_block,
        new_signatures,
        &params.pubkey_list,
        shared_secrets,
        &block_shared_keys,
        &shared_block_secrets,
        priv_shared_keys,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            log::error!("aggregated signature is invalid. e: {:?}", e);
            return prev_state.clone();
        }
    };

    let completed_block = match submitblock(candidate_block, &signature, &params.rpc) {
        Ok(block) => block,
        Err(e) => {
            log::error!("block rejected by Tapyrus Core: {:?}", e);
            return state_builder.build();
        }
    };

    log::info!(
        "Round Success. caindateblock(block hash for sign)={:?} completedblock={:?}",
        candidate_block.sighash(),
        completed_block.hash()
    );

    // send completeblock message
    broadcast_completedblock(completed_block, &params.signer_id, conman);

    return state_builder.round_is_done(true).build();
}

fn store_received_local_sig(
    sender_id: &SignerID,
    signatures: &BTreeMap<SignerID, (FE, FE)>,
    gamma_i: FE,
    e: FE,
) -> BTreeMap<SignerID, (FE, FE)> {
    let mut result = signatures.clone();
    result.insert(sender_id.clone(), (gamma_i, e));
    result
}

fn aggregate_and_verify_signature(
    block: &Block,
    signatures: BTreeMap<SignerID, (FE, FE)>,
    pubkey_list: &Vec<PublicKey>,
    shared_secrets: &SharedSecretMap,
    block_shared_keys: &Option<(bool, FE, GE)>,
    shared_block_secrets: &BidirectionalSharedSecretMap,
    priv_shared_keys: &SharedKeys,
) -> Result<Signature, Error> {
    let parties = signatures
        .keys()
        .map(|k| sender_index(k, pubkey_list))
        .collect::<Vec<usize>>();
    let key_gen_vss_vec: Vec<VerifiableSS> = shared_secrets.to_vss();
    let local_sigs: Vec<LocalSig> = signatures
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

    match LocalSig::verify_local_sigs(&local_sigs, &parties[..], &key_gen_vss_vec, &eph_vss_vec) {
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
            Err(Error::InvalidSig)
        }
    }
}

fn submitblock<T>(block: &Block, sig: &Signature, rpc: &std::sync::Arc<T>) -> Result<Block, Error>
where
    T: TapyrusApi,
{
    let sig_hex = Sign::format_signature(sig);
    let new_block: Block = block.add_proof(hex::decode(sig_hex).unwrap());
    match rpc.submitblock(&new_block) {
        Ok(_) => Ok(new_block),
        Err(e) => Err(e),
    }
}

fn broadcast_completedblock<C>(block: Block, own_id: &SignerID, conman: &C)
where
    C: ConnectionManager,
{
    log::info!("Broadcast CompletedBlock message. {:?}", block.hash());
    let message = Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Completedblock(block),
        ),
        sender_id: own_id.clone(),
        receiver_id: None,
    };
    conman.broadcast_message(message);
}

#[cfg(test)]
mod tests {
    use super::process_blocksig;
    use crate::blockdata::hash::Hash;
    use crate::crypto::multi_party_schnorr::SharedKeys;
    use crate::net::SignerID;
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::signer_node::*;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_state_builder::BuilderForTest;
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;
    use curv::FE;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::iter::FromIterator;

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
