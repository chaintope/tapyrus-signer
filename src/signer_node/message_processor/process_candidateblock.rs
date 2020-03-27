use crate::blockdata::Block;
use crate::net::{ConnectionManager, SignerID};
use crate::rpc::TapyrusApi;
use crate::signer_node::message_processor::create_block_vss;
use crate::signer_node::node_state::builder::{Builder, Member};
use crate::signer_node::utils::sender_index;
use crate::signer_node::{NodeParameters, NodeState};

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
    // Ignore the message when the sender is myself.
    if *sender_id == params.signer_id {
        return prev_state.clone();
    }

    log::info!(
        "candidateblock received. block hash for signing: {:?}",
        block.sighash()
    );

    match &prev_state {
        NodeState::Member { .. } => {
            if let Err(e) = params.rpc.testproposedblock(&block) {
                log::warn!(
                    "Received Invalid candidate block sender: {}, {:?}",
                    sender_id,
                    e
                );
                return prev_state.clone();
            }

            let (key, shared_secret_for_positive, shared_secret_for_negative) =
                create_block_vss(block.clone(), params, conman);

            Member::from_node_state(prev_state.clone())
                .block_key(Some(key.u_i))
                .candidate_block(Some(block.clone()))
                .master_index(sender_index(sender_id, &params.pubkey_list))
                .insert_shared_block_secrets(
                    params.signer_id.clone(),
                    shared_secret_for_positive,
                    shared_secret_for_negative,
                )
                .build()
        }
        _ => prev_state.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::process_candidateblock;
    use crate::blockdata::Block;
    use crate::net::MessageType::BlockGenerationRoundMessages;
    use crate::net::{BlockGenerationRoundMessageType, Message, SignerID};
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::signer_node::{master_index, NodeState};
    use crate::tests::helper::blocks::get_block;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::net::TestConnectionManager;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::node_state_builder::BuilderForTest;
    use crate::tests::helper::rpc::MockRpc;

    fn sender_id() -> SignerID {
        TEST_KEYS.signer_ids()[1]
    }

    /// This network consists 5 signers and threshold 3.
    #[test]
    fn test_as_member_with_valid_args() {
        let sender_id = sender_id();
        let candidate_block = get_block(0);
        let prev_state = Member::for_test().build();
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

        // It should send 4 blockvss messages to each signer (except myself).
        let sent_messages = conman.sent.borrow();
        assert_eq!(sent_messages.len(), 4);
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

    /// This is a case of receiving own candidateblock message.
    /// It should ignore the message because it is from myself and already have.
    #[test]
    fn test_as_master_with_valid_args() {
        let sender_id = sender_id();
        let candidate_block = get_block(0);
        let prev_state = Master::for_test()
            .candidate_block(Some(candidate_block.clone()))
            .build();
        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        let next_state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);

        assert_eq!(prev_state, next_state);
        params.rpc.assert();
    }

    #[test]
    fn test_as_master_with_invalid_block() {
        let sender_id = sender_id();
        // invalid block
        let candidate_block = Block::new(hex::decode("00000020ed658cc40670cceda23bb0b614821fe6d48a41d107d19f3f3a5608ad3d483092b151160ab71133b428e1f62eaeb598ae858ff66017c99601f29088b7c64a481d6284e145d29b70bf54392d29701031d2af9fed5f9bb21fbb284fa71ceb238f69a6d4095d00010200000000010100000000000000000000000000000000000000000000000000000000000000000c000000035c0101ffffffff0200f2052a010000001976a914cf12dbc04bb0de6fb6a87a5aeb4b2e74c97006b288ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());
        let prev_state = Master::for_test().build();
        let conman = TestConnectionManager::new();
        let rpc = MockRpc::new();
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        let next_state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);

        // It should not be changed any thing.
        assert_eq!(next_state, prev_state);

        // It should not send any message.
        let sent_messages = conman.sent.borrow();
        assert_eq!(sent_messages.len(), 0);

        params.rpc.assert();
    }

    #[test]
    fn test_as_member_with_invalid_block() {
        let sender_id = sender_id();
        // invalid block
        let candidate_block = Block::new(hex::decode("00000020ed658cc40670cceda23bb0b614821fe6d48a41d107d19f3f3a5608ad3d483092b151160ab71133b428e1f62eaeb598ae858ff66017c99601f29088b7c64a481d6284e145d29b70bf54392d29701031d2af9fed5f9bb21fbb284fa71ceb238f69a6d4095d00010200000000010100000000000000000000000000000000000000000000000000000000000000000c000000035c0101ffffffff0200f2052a010000001976a914cf12dbc04bb0de6fb6a87a5aeb4b2e74c97006b288ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());
        let prev_state = Member::for_test().build();
        let conman = TestConnectionManager::new();
        let mut rpc = MockRpc::new();

        // It should call testproposedblock RPC once.
        rpc.should_call_testproposedblock_and_returns_invalid_block_error();
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        let next_state =
            process_candidateblock(&sender_id, &candidate_block, &prev_state, &conman, &params);

        // It should not set candidate_block into return state.
        assert_eq!(prev_state, next_state);

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
    /// 1. Send candidateblock message from index 0 node(array index is 4).
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

        let prev_state = Member::for_test().master_index(0).build();
        let params = NodeParametersBuilder::new()
            .public_key(TEST_KEYS.pubkeys()[2])
            .rpc(rpc)
            .build();

        // Step 1.
        let sender_id = SignerID::new(TEST_KEYS.pubkeys()[4]);
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
