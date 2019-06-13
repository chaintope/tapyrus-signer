use crate::net::{ConnectionManager, RedisManager, MessageType, Message};
use crate::signer::{RoundState, StateContext, NodeState};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey};
use serde_json::error::ErrorCode::ControlCharacterWhileParsingString;

pub struct SignerNode<T: ConnectionManager> {
    connection_manager: T,
    state_context: StateContext,
    params: NodeParameters,
}

impl<T: ConnectionManager> SignerNode<T> {
    pub fn new(connection_manager: T, state_context: StateContext, params: NodeParameters) -> SignerNode<T> {
        SignerNode {
            connection_manager,
            state_context,
            params,
        }
    }

    pub fn start(&mut self) {
        let closure = |message: Message| {
            let next = match message.message_type {
                MessageType::Candidateblock => self.state_context.current_state.process().process_candidateblock(&message.payload[..]),
                _ => NodeState::Joining,
//                MessageType::Signature => { round_state.process_signature(&message.payload[..]) },
//                MessageType::Completedblock => { round_state.process_completedblock(&message.payload[..]) },
//                MessageType::Roundfailure => { round_state.process_roundfailure(&message.payload[..]) },
            };

//            self.state_context.set_state(next);
            ControlFlow::Continue
        };
        self.connection_manager.start(closure);
    }
}

pub struct NodeParameters {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u32,
    pub privateKey: PrivateKey,
}
