use crate::crypto::multi_party_schnorr::Signature;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::{ConnectionManager, Message, MessageType, SignerID};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::message_processor::get_valid_block;
use crate::signer_node::node_state::builder::{Builder, Master};
use crate::signer_node::NodeParameters;
use crate::signer_node::NodeState;
use curv::FE;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tapyrus::blockdata::block::Block;
use tapyrus::consensus::encode::deserialize;
use tapyrus::hash_types::BlockSigHash;
use tapyrus::PublicKey;

pub fn process_blocksig<T, C>(
    sender_id: &SignerID,
    blockhash: BlockSigHash,
    gamma_i: FE,
    e: FE,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let block_height = prev_state.block_height();

    #[cfg(feature = "dump")]
    let mut dump_builder = {
        let mut builder = DumpBuilder::default();
        let federation = params.get_federation_by_block_height(block_height);
        let node_vss = federation.nodevss();
        let aggregated_public_key = federation.aggregated_public_key();
        builder
            .received(Received {
                sender: sender_id.clone(),
                block_hash: blockhash,
                gamma_i,
                e,
            })
            .public_keys(params.pubkey_list(block_height).clone())
            .threshold(params.threshold(block_height) as usize)
            .public_key(params.signer_id.pubkey)
            .prev_state(prev_state.clone())
            .aggregated_public_key(aggregated_public_key)
            .node_vss(node_vss.clone());
        builder
    };
    // extract values from state object.
    let (block_shared_keys, shared_block_secrets, signatures, participants) = match prev_state {
        NodeState::Master {
            block_shared_keys,
            shared_block_secrets,
            signatures,
            round_is_done: false,
            participants,
            ..
        } => (
            block_shared_keys,
            shared_block_secrets,
            signatures,
            participants,
        ),
        _ => {
            // Ignore blocksig message except Master state which is not done.
            #[cfg(feature = "dump")]
            dump_builder.build().unwrap().log();
            return prev_state.clone();
        }
    };

    // Ignore the message if the sender is not contained in the participants.
    if !participants.contains(sender_id) {
        #[cfg(feature = "dump")]
        dump_builder.build().unwrap().log();
        return prev_state.clone();
    }

    let mut state_builder = Master::from_node_state(prev_state.clone());

    log::debug!(
        "Store local sig, sender: {:?}, gamma_i: {:?}, e: {:?}",
        sender_id,
        gamma_i,
        e
    );
    let new_signatures = store_received_local_sig(sender_id, signatures, gamma_i, e);
    state_builder.signatures(new_signatures.clone());

    log::trace!(
        "number of signatures: {:?} (threshold: {:?})",
        new_signatures.len(),
        params.threshold(block_height)
    );

    let candidate_block = match get_valid_block(prev_state, blockhash) {
        Ok(block) => block,
        Err(_) => {
            #[cfg(feature = "dump")]
            dump_builder.build().unwrap().log();
            return prev_state.clone();
        }
    };

    // Check whether the number of signatures met the threshold
    if new_signatures.len() < params.threshold(block_height) as usize {
        #[cfg(feature = "dump")]
        dump_builder.build().unwrap().log();
        return state_builder.build();
    }

    if block_shared_keys.is_none() {
        log::error!("key is not shared.");
        #[cfg(feature = "dump")]
        dump_builder.build().unwrap().log();
        return prev_state.clone();
    }

    let shared_block_secrets_by_participants = shared_block_secrets
        .clone()
        .into_iter()
        .filter(|(i, ..)| participants.contains(i))
        .collect();

    let federation = params.get_federation_by_block_height(block_height);

    let signature = match Vss::aggregate_and_verify_signature(
        candidate_block,
        new_signatures,
        &params.pubkey_list(block_height),
        &federation.node_shared_secrets(),
        &block_shared_keys,
        &shared_block_secrets_by_participants,
        &federation.node_secret_share(),
    ) {
        Ok(sig) => sig,
        Err(e) => {
            log::error!("aggregated signature is invalid. e: {:?}", e);
            #[cfg(feature = "dump")]
            dump_builder.build().unwrap().log();
            return prev_state.clone();
        }
    };

    let completed_block = match submitblock(candidate_block, &signature, &params.rpc) {
        Ok(block) => block,
        Err(e) => {
            log::error!("block rejected by Tapyrus Core: {:?}", e);

            #[cfg(feature = "dump")]
            dump_builder.build().unwrap().log();
            return state_builder.build();
        }
    };

    log::info!(
        "Round Success. candidateblock(block hash for sign)={:?}",
        candidate_block.header.signature_hash(),
    );

    #[cfg(feature = "dump")]
    dump_builder
        .completed_block(completed_block.clone())
        .build()
        .unwrap()
        .log();

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

fn submitblock<T>(block: &Block, sig: &Signature, rpc: &std::sync::Arc<T>) -> Result<Block, Error>
where
    T: TapyrusApi,
{
    let sig_hex = Sign::format_signature(sig);
    let mut new_block = block.clone();
    new_block.header.proof = Some(deserialize(
        &hex::decode(sig_hex).map_err(|_| Error::InvalidSig)?,
    )?);
    match rpc.submitblock(&new_block) {
        Ok(_) => Ok(new_block),
        Err(e) => Err(e),
    }
}

fn broadcast_completedblock<C>(block: Block, own_id: &SignerID, conman: &C)
where
    C: ConnectionManager,
{
    log::info!("Broadcast CompletedBlock message.");
    let message = Message {
        message_type: MessageType::Completedblock(block),
        sender_id: own_id.clone(),
        receiver_id: None,
    };
    conman.broadcast_message(message);
}

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct Dump {
    public_keys: Vec<PublicKey>,
    threshold: usize,
    public_key: PublicKey,
    node_vss: Vec<Vss>,
    received: Received,
    prev_state: NodeState,
    aggregated_public_key: PublicKey,
    #[builder(setter(strip_option), default)]
    completed_block: Option<Block>,
}

impl Dump {
    #[allow(dead_code)]
    fn log(&self) {
        log::debug!("Dump: {}", serde_json::to_string(self).unwrap());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Received {
    sender: SignerID,
    block_hash: BlockSigHash,
    gamma_i: FE,
    e: FE,
}

#[cfg(test)]
mod tests {
    use super::process_blocksig;
    use crate::federation::{Federation, Federations};
    use crate::net::Message;
    use crate::signer_node::message_processor::process_blocksig::Dump;
    use crate::signer_node::*;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::test_vectors::*;

    #[test]
    fn test_process_blocksig_for_member() {
        // if node state is Member, process_blocksig should return Member state(it is same as prev_state).
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();
        let dump: Dump =
            serde_json::from_value(contents["cases"]["process_blocksig_for_member"].clone())
                .unwrap();
        let conman = TestConnectionManager::new();
        let params = NodeParametersBuilder::new()
            .rpc(MockRpc::new())
            .public_key(dump.public_key)
            .build();

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, dump.prev_state);
        params.rpc.assert();
        conman.assert();
    }

    #[test]
    fn test_process_blocksig_invalid_block() {
        // if node receives invalid block (that means block is not the same as candidate block),
        // node should return prev_state immediately.
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();
        let dump: Dump =
            serde_json::from_value(contents["cases"]["process_blocksig_invalid_block"].clone())
                .unwrap();
        let conman = TestConnectionManager::new();
        let params = NodeParametersBuilder::new()
            .rpc(MockRpc::new())
            .public_key(dump.public_key)
            .build();

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, dump.prev_state);
        params.rpc.assert();
        conman.assert();
    }

    #[test]
    fn test_process_blocksig_1_valid_block() {
        // when node
        //  - receives a valid block,
        //  - but the number of signatures(1) is not enough (2) to generate an aggregated signature,
        // node should return new Master state which has signatures.
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();
        let dump: Dump =
            serde_json::from_value(contents["cases"]["process_blocksig_1_valid_block"].clone())
                .unwrap();
        let conman = TestConnectionManager::new();
        let params = NodeParametersBuilder::new()
            .rpc(MockRpc::new())
            .public_key(dump.public_key)
            .build();

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
            &conman,
            &params,
        );

        params.rpc.assert();
        conman.assert();

        match dump.prev_state {
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
    fn test_process_blocksig_from_non_participants() {
        // when node
        //  - receive from non-paticipants member.
        // node should return previous node state.
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();
        let dump: Dump = serde_json::from_value(
            contents["cases"]["process_blocksig_from_non_participants"].clone(),
        )
        .unwrap();
        let conman = TestConnectionManager::new();
        let params = NodeParametersBuilder::new()
            .rpc(MockRpc::new())
            .public_key(dump.public_key)
            .build();

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, dump.prev_state);
        params.rpc.assert();
        conman.assert();
    }

    #[test]
    fn test_process_blocksig_receiving_invalid_signature() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - but received gamma_i and e is invalid.
        // node should return prev_state.
        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();
        let dump: Dump = serde_json::from_value(
            contents["cases"]["process_blocksig_receiving_invalid_signature"].clone(),
        )
        .unwrap();
        let conman = TestConnectionManager::new();
        let federations = vec![Federation::new(
            dump.public_key,
            0,
            Some(dump.threshold as u8),
            Some(dump.node_vss.clone()),
            dump.aggregated_public_key,
        )];
        let federations = Federations::new(federations);
        let params = NodeParametersBuilder::new()
            .rpc(MockRpc::new())
            .public_key(dump.public_key)
            .federations(federations)
            .build();

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, dump.prev_state);
        params.rpc.assert();
        conman.assert();
    }

    #[test]
    fn test_process_blocksig_with_invalid_signature() {
        // when node
        //  - receives a valid block,
        //  - has the number of signatures to generate a aggregated signature,
        //  - and received gamma_i and e is valid.
        //  - but node already received invalid signature from other node
        // node should return prev_state.

        let contents = load_test_vector("./tests/resources/process_blocksig.json").unwrap();
        let dump: Dump = serde_json::from_value(
            contents["cases"]["process_blocksig_with_invalid_signature"].clone(),
        )
        .unwrap();
        let conman = TestConnectionManager::new();
        let federations = vec![Federation::new(
            dump.public_key,
            0,
            Some(dump.threshold as u8),
            Some(dump.node_vss.clone()),
            dump.aggregated_public_key,
        )];
        let federations = Federations::new(federations);
        let params = NodeParametersBuilder::new()
            .rpc(MockRpc::new())
            .public_key(dump.public_key)
            .federations(federations)
            .build();

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
            &conman,
            &params,
        );

        assert_eq!(next, dump.prev_state);
        params.rpc.assert();
        conman.assert();
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
        let dump: Dump =
            serde_json::from_value(contents["cases"]["process_blocksig_successfully"].clone())
                .unwrap();
        let mut rpc = MockRpc::new();
        rpc.should_call_submitblock(Ok(()));
        let federations = vec![Federation::new(
            dump.public_key,
            0,
            Some(dump.threshold as u8),
            Some(dump.node_vss.clone()),
            dump.aggregated_public_key,
        )];
        let federations = Federations::new(federations);
        let params = NodeParametersBuilder::new()
            .rpc(rpc)
            .public_key(dump.public_key)
            .federations(federations)
            .build();

        let mut conman = TestConnectionManager::new();
        conman.should_broadcast(Message {
            message_type: MessageType::Completedblock(dump.completed_block.unwrap().clone()),
            sender_id: params.signer_id,
            receiver_id: None,
        });

        let next = process_blocksig(
            &dump.received.sender,
            dump.received.block_hash.clone(),
            dump.received.gamma_i.clone(),
            dump.received.e.clone(),
            &dump.prev_state,
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
}
