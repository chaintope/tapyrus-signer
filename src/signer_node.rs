use crate::net::{ConnectionManager, Message};
use crate::signer::{StateContext};
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

    pub fn start(&mut self) {
        let mut context: StateContext = StateContext::new();
        let closure = move |message: Message| {
            let next = context.current_state.process(message);
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
