use crate::net::{ConnectionManager, MessageType, Message};
use crate::signer::{StateContext};
use crate::net::{ConnectionManager, Message};
use crate::signer::{StateContext, NodeState};
use redis::ControlFlow;
use bitcoin::{PublicKey, PrivateKey};
use std::sync::mpsc::channel;

pub struct SignerNode<T: ConnectionManager> {
    connection_manager: T,
    _params: NodeParameters,
}

impl<T: ConnectionManager> SignerNode<T> {
    pub fn new(connection_manager: T, _params: NodeParameters) -> SignerNode<T> {
        SignerNode {
            connection_manager,
            _params,
        }
    }

    pub fn start(&mut self, state: NodeState) {
        let mut context: StateContext = StateContext::new(state);
        let closure = move |message: Message| {
            let next = context.current_state.process_message(message);
            context.set_state(next);
            ControlFlow::Continue
        };
        self.connection_manager.start(closure);
    }
}

pub struct NodeParameters {
    pub pubkey_list: Vec<PublicKey>,
    pub threshold: u32,
    pub private_key: PrivateKey,
}
