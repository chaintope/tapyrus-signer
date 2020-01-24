use crate::blockdata::Block;
use crate::net::{
    BlockGenerationRoundMessageType, ConnectionManager, Message, MessageType, SignerID,
};
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::utils::sender_index;
use crate::signer_node::{NodeParameters, NodeState};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, FE};
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::Keys;

pub fn process_candidateblock<T, C>(
    sender_id: &SignerID,
    block: &Block,
    prev_state: &NodeState,
    conman: &C,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    log::info!(
        "candidateblock received. block hash for signing: {:?}",
        block.sighash()
    );

    match &prev_state {
        NodeState::Member {
            shared_block_secrets,
            block_shared_keys,
            master_index,
            ..
        } => {
            match params.rpc.testproposedblock(&block) {
                Ok(_) => {
                    let key = create_block_vss(block.clone(), params, conman);
                    // TODO: Errorを処理する必要あるかな？
                    NodeState::Member {
                        block_key: Some(key.u_i),
                        shared_block_secrets: shared_block_secrets.clone(),
                        block_shared_keys: block_shared_keys.clone(),
                        candidate_block: Some(block.clone()),
                        master_index: sender_index(sender_id, &params.pubkey_list),
                    }
                }
                Err(_e) => {
                    log::warn!("Received Invalid candidate block sender: {}", sender_id);
                    NodeState::Member {
                        block_key: None,
                        shared_block_secrets: shared_block_secrets.clone(),
                        block_shared_keys: block_shared_keys.clone(),
                        candidate_block: Some(block.clone()),
                        master_index: *master_index,
                    }
                }
            }
        }
        NodeState::Master {
            block_shared_keys,
            shared_block_secrets,
            signatures,
            round_is_done: false,
            ..
        } => {
            let key = create_block_vss(block.clone(), params, conman);
            NodeState::Master {
                block_key: Some(key.u_i),
                block_shared_keys: block_shared_keys.clone(),
                shared_block_secrets: shared_block_secrets.clone(),
                candidate_block: block.clone(),
                signatures: signatures.clone(),
                round_is_done: false,
            }
        }
        _ => prev_state.clone(),
    }
}

fn create_block_vss<T, C>(block: Block, params: &NodeParameters<T>, conman: &C) -> Keys
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let sharing_params = params.sharing_params();
    let key = Sign::create_key(params.self_node_index + 1, None);

    let parties = (0..sharing_params.share_count)
        .map(|i| i + 1)
        .collect::<Vec<usize>>();

    let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
        sharing_params.threshold,
        sharing_params.share_count,
        &key.u_i,
        &parties,
    );
    let order: BigInt = FE::q();
    let (vss_scheme_for_negative, secret_shares_for_negative) = VerifiableSS::share_at_indices(
        sharing_params.threshold,
        sharing_params.share_count,
        &(ECScalar::from(&(order - key.u_i.to_big_int()))),
        &parties,
    );
    for i in 0..params.pubkey_list.len() {
        conman.send_message(Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Blockvss(
                    block.sighash(),
                    vss_scheme.clone(),
                    secret_shares[i],
                    vss_scheme_for_negative.clone(),
                    secret_shares_for_negative[i],
                ),
            ),
            sender_id: params.signer_id,
            receiver_id: Some(SignerID {
                pubkey: params.pubkey_list[i],
            }),
        });
    }
    key
}

#[cfg(test)]
mod tests {
    use super::process_candidateblock;
    use crate::blockdata::Block;
    use crate::errors::Error;
    use crate::net::MessageType::BlockGenerationRoundMessages;
    use crate::net::{BlockGenerationRoundMessageType, Message, SignerID};
    use crate::signer_node::{master_index, NodeParameters, NodeState};
    use crate::tests::helper::blocks::get_block;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::node_state_builder::{Builder, Member};
    use crate::tests::helper::rpc::MockRpc;
    use crate::tests::helper::{address, enable_log};

    /// This network consists 5 signers and threshold 3.
    #[test]
    fn test_with_valid_args() {
        let sender_id = TEST_KEYS.signer_id();
        let candidate_block = get_block(0);
        let prev_state = Member::new().build();
        let conman = TestConnectionManager::new();
        let mut rpc = MockRpc::new();
        // It should call testproposedblock RPC once.
        rpc.should_call_testproposedblock(Ok(true));
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        let next_state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);

        // It should set candidate_block into return state.
        match next_state {
            NodeState::Member {
                candidate_block: Some(block),
                ..
            } => assert_eq!(candidate_block, block),
            _ => assert!(false),
        }

        // It should send 5 blockvss messages to each signer (includes myself).
        let sent_messages = conman.sent.borrow();
        assert_eq!(sent_messages.len(), 5);
        for message_type in sent_messages.iter() {
            match message_type {
                Message {
                    message_type:
                        BlockGenerationRoundMessages(BlockGenerationRoundMessageType::Blockvss(..)),
                    ..
                } => assert!(true),
                m => assert!(false, format!("Sent unexpected message {:?}", m)),
            }
        }

        params.rpc.assert();
    }

    #[test]
    fn test_with_invalid_block() {
        enable_log(None);
        let sender_id = TEST_KEYS.signer_id();
        // invalid block
        let candidate_block = Block::new(hex::decode("00000020ed658cc40670cceda23bb0b614821fe6d48a41d107d19f3f3a5608ad3d483092b151160ab71133b428e1f62eaeb598ae858ff66017c99601f29088b7c64a481d6284e145d29b70bf54392d29701031d2af9fed5f9bb21fbb284fa71ceb238f69a6d4095d00010200000000010100000000000000000000000000000000000000000000000000000000000000000c000000035c0101ffffffff0200f2052a010000001976a914cf12dbc04bb0de6fb6a87a5aeb4b2e74c97006b288ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());
        let prev_state = Member::new().build();
        let conman = TestConnectionManager::new();
        let mut rpc = MockRpc::new();

        // It should call testproposedblock RPC once.
        let err = Error::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError {
            code: -25,
            message: "proposal was not based on our best chain".to_string(),
            data: None,
        }));
        rpc.should_call_testproposedblock(Err(err));
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        let next_state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);

        // It should set candidate_block into return state.
        match next_state {
            NodeState::Member {
                candidate_block: Some(block),
                ..
            } => assert_eq!(candidate_block, block),
            _ => assert!(false),
        }

        // It should not send any blockvss messages to each signer.
        assert_eq!(conman.sent.borrow().len(), 0);

        params.rpc.assert();
    }

    /// When a node's state is Member, the node receives candidateblock message from the other
    /// node who are not assumed as a master of the round, the node change the assumption to
    /// that the other node is master.
    ///
    /// The test scenario is below.
    ///
    /// *premise:*
    /// * The node's status is Member and its index is 4.
    /// * The round master's index is 0.
    ///
    /// 1. Send candidateblock message from index 0 node(array index is 1).
    ///    It must not change master_index assumption.
    /// 2. Send candidateblock message from index 4 node(array index is 0).
    ///    It must change master_index assumption to 4.
    #[test]
    fn test_modify_master_index() {
        let candidate_block = get_block(0);
        let conman = TestConnectionManager::new();
        let mut rpc = MockRpc::new();
        // It should call testproposedblock RPC once for each execution of process_candidateblock().
        rpc.should_call_testproposedblock(Ok(true));
        rpc.should_call_testproposedblock(Ok(true));

        let prev_state = Member::new().master_index(0).build();
        let params = NodeParametersBuilder::new()
            .private_key(TEST_KEYS.key[0])
            .rpc(rpc)
            .build();

        // Step 1.
        let sender_id = SignerID::new(TEST_KEYS.pubkeys()[1]);
        let state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);
        assert_eq!(master_index(&state, &params).unwrap(), 0);

        // Step 2.
        let sender_id = SignerID::new(TEST_KEYS.pubkeys()[0]);
        let state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);
        assert_eq!(master_index(&state, &params).unwrap(), 4);

        params.rpc.assert();
    }
}
